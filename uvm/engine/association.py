"""Per-Finding API association read-back normaliser
(FindingDetailAssociationV1).

Pure stdlib, versioned contract for the CE supported read-back boundary
(CR-01/04). No HTTP, no persistence, no engine calls. The contract follows
``openspec/changes/g1-engine-identity-contracts/design.md``: a settled
occurrence link needs a verified endpoint, component locator or other
parser-specific source-record association, and a shared Finding ID alone
does not prove CR-04.

The CE 3.3.100/3.3.200 supported API exposes ``GET /api/v2/findings/{id}/``
whose response binds one Finding to its own ``endpoints`` list, its
optional ``component_name``/``component_version``, its ``test`` and its
``verified`` flag. The ``verified`` field is CE's manual vulnerability
verification field: it says nothing about whether the read-back itself is
trusted, and this normaliser never treats it as read-back or association
trust. The caller supplies a bounded ``source_kind`` label (one of
``SOURCE_KINDS``) that names the origin of the retained bytes as inert
metadata only; no accepted value claims a trusted live read-back, and a
label outside the bounded set is rejected. The flat
``uvm.engine.operation.FindingReadbackV1`` scope retains only ID sets: it
cannot bind a specific Endpoint to a specific Finding. This normaliser
keeps the association per-Finding instead of flattening it into one ID
pool:

- one ``FindingDetailAssociationV1`` describes exactly one Finding of
  exactly one Test, as requested and as returned by the API;
- a mismatch between the requested Finding/Test ID and the returned
  ``id``/``test`` is malformed, never relabelled; a caller cannot use
  Finding f1's read-back to claim Finding f2's endpoints;
- ``endpoint_ids`` is the exact set attached to that Finding in the
  response: an empty tuple is an honest endpoint-less Finding (the
  Sysdig component shape), a missing ``endpoints`` key is malformed —
  missing and empty are distinct;
- an unknown or missing component stays unknown (explicit ``None``); no
  port or occurrence identity is ever inferred from the description
  text;
- the raw read-back bytes are the ONLY source of both the parsed fields
  and the digest: there is no separate decoded-body input that could
  diverge from the bytes; the bytes must decode to a JSON object;
- ``ce_verified`` is the response's explicit ``verified`` flag, taken
  as-is and labelled as CE's manual verification only — a malformed or
  partial read-back raises and never yields a DTO;
- ``evidence_sha256`` must be the sha256 hex digest of the actual raw
  read-back bytes (``body_bytes``); a non-digest string or a mismatched
  digest is rejected — an arbitrary ref or digest is never accepted as
  proof; the DTO fields and the digest therefore always describe the
  same retained bytes.

When an Endpoint detail response exposes a reverse ``findings`` list,
``parse_endpoint_detail`` retains that exact reverse membership as a separate
typed contract. Some supported CE 3.3.100 public responses omit that field;
``parse_endpoint_identity_detail`` can then prove only that the requested
Endpoint exists and returned its exact ID. The Finding detail's exact forward
``endpoints`` list remains the source of the Finding-to-Endpoint edge. An
identity-only Endpoint DTO never claims reverse membership.

The test-filtered Findings list is paginated:
``findings_readback_covers`` validates that a retained list read-back is
complete and count-covered: every page must agree on the reported
``count``, and every item must belong to the requested Test ID — a
list mixing Findings from another Test, or with disagreeing page
counts, is never complete. It validates shape and coverage only; it is
never CR-04 proof, which remains the concern of ``uvm.engine.link``.

Synthetic-fixture scope only: nothing here is durable persistence, live
API integration or external-system evidence. The labelled smoke in the test
module re-parses the retained CE 3.3.200 comparison-run artifacts only.

This module is an association projection only: it validates the bounded
fields needed for these typed associations, not a whole-object OpenAPI
response contract or artifact authenticity/verification. ``evidence_ref`` is
a caller-supplied label for the retained bytes; only ``evidence_sha256`` is
checked against ``body_bytes`` here.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

SCHEMA_VERSION = 1

# Bounded, inert origin labels for retained read-back bytes. No value
# implies a trusted live read-back; caller labels outside this set are
# malformed.
SOURCE_KINDS = ("retained-artifact", "synthetic-fixture")

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def _require_str(value, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")


def _require_source_kind(value, name: str) -> None:
    # Check the runtime type before membership: a custom object can spoof
    # equality with an allowed label and otherwise pass ``value in``.
    # Exact ``str`` also keeps the DTO's retained label an ordinary string,
    # excluding bools and custom str subclasses.
    if type(value) is not str or value not in SOURCE_KINDS:
        raise ValueError(
            f"{name} must be one of {SOURCE_KINDS!r}; a caller label "
            "outside the bounded set cannot claim a trusted live "
            "read-back and is rejected"
        )


def _require_digest(value, name: str) -> None:
    if not isinstance(value, str) or not _SHA256_HEX_RE.match(value):
        raise ValueError(
            f"{name} must be a 64-character lowercase sha256 hex digest, "
            f"got {value!r}"
        )


def _reject_duplicate_keys(pairs):
    """object_pairs_hook for decoding the raw read-back body: any repeated
    JSON object key (conflicting or otherwise) is malformed and rejected,
    never silently resolved last-wins."""
    seen = set()
    dupes = set()
    for key, _ in pairs:
        if key in seen:
            dupes.add(key)
        seen.add(key)
    if dupes:
        raise ValueError(
            f"read-back body has duplicate JSON object keys "
            f"{sorted(dupes)!r}; duplicate keys are not accepted"
        )
    return dict(pairs)


def _reject_non_finite_json_constant(value):
    """Reject Python's non-standard JSON constants (NaN and infinities)."""
    raise ValueError(
        f"non-finite JSON constant {value!r} is not valid JSON"
    )


def _api_id(value, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer, got {value!r}")
    return value


@dataclass(frozen=True, init=False)
class FindingDetailAssociationV1:
    """One versioned per-Finding association from a supported
    ``GET /api/v2/findings/{id}/`` read-back.

    ``endpoint_ids`` is the exact Endpoint set the response attaches to
    this one Finding: an empty tuple means the Finding genuinely has no
    endpoints (some parsers create none); it is never the flat Test-level
    Endpoint pool. ``component_name``/``component_version`` are explicit
    ``None`` when the response reports no component: unknown stays
    unknown, and the description text is never mined for a port or an
    occurrence identity. ``ce_verified`` is the response's explicit
    ``verified`` flag — CE's manual vulnerability verification — taken
    as-is; it is not a read-back or association trust and must never be
    read as one. ``source_kind`` is a bounded inert label (one of
    ``SOURCE_KINDS``) naming the origin of the retained bytes; it is
    never derived from ``ce_verified`` and no accepted value implies a
    trusted live read-back. ``evidence_sha256`` is the sha256 hex digest
    of the actual raw read-back bytes, which are also the only source
    of the parsed fields; the parser verifies the digest against those
    bytes before the DTO can exist. ``parse_finding_detail`` is the only
    construction path: direct construction is rejected, so a digest field
    alone can never fabricate a body-verified association.
    """

    # required
    schema_version: int
    ce_release: str  # explicit CE release the read-back was taken from
    test_id: int  # the Finding's Test, as returned
    finding_id: int  # the Finding this association is about
    endpoint_ids: tuple  # Endpoint IDs attached to this Finding (may be empty)
    component_name: Optional[str]  # None = unknown, never inferred
    component_version: Optional[str]  # None = unknown, never inferred
    evidence_ref: str  # retained read-back evidence reference
    evidence_sha256: str  # sha256 of the raw read-back bytes
    ce_verified: bool  # CE manual vulnerability verification flag only
    source_kind: str  # bounded inert origin label (SOURCE_KINDS), never
                      # derived from ce_verified; never implies a
                      # trusted live read-back

    def __init__(self, *args, **kwargs):
        raise ValueError(
            "FindingDetailAssociationV1 cannot be constructed directly: "
            "a digest field alone does not prove a body read-back. Use "
            "parse_finding_detail, the only verified construction path, "
            "which binds evidence_sha256 to the raw read-back bytes it "
            "parsed."
        )

    @classmethod
    def _from_parsed(
        cls,
        *,
        schema_version: int,
        ce_release: str,
        test_id: int,
        finding_id: int,
        endpoint_ids: tuple,
        component_name: Optional[str],
        component_version: Optional[str],
        evidence_ref: str,
        evidence_sha256: str,
        ce_verified: bool,
        source_kind: str,
    ) -> "FindingDetailAssociationV1":
        obj = object.__new__(cls)
        object.__setattr__(obj, "schema_version", schema_version)
        object.__setattr__(obj, "ce_release", ce_release)
        object.__setattr__(obj, "test_id", test_id)
        object.__setattr__(obj, "finding_id", finding_id)
        object.__setattr__(obj, "endpoint_ids", endpoint_ids)
        object.__setattr__(obj, "component_name", component_name)
        object.__setattr__(obj, "component_version", component_version)
        object.__setattr__(obj, "evidence_ref", evidence_ref)
        object.__setattr__(obj, "evidence_sha256", evidence_sha256)
        object.__setattr__(obj, "ce_verified", ce_verified)
        object.__setattr__(obj, "source_kind", source_kind)
        obj.__post_init__()
        return obj

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version!r}")
        _require_str(self.ce_release, "ce_release")
        _api_id(self.test_id, "test_id")
        _api_id(self.finding_id, "finding_id")
        if not isinstance(self.endpoint_ids, tuple):
            raise ValueError("endpoint_ids must be a tuple")
        for endpoint_id in self.endpoint_ids:
            _api_id(endpoint_id, "endpoint id")
        if len(set(self.endpoint_ids)) != len(self.endpoint_ids):
            raise ValueError("endpoint_ids must not contain duplicates")
        for name in ("component_name", "component_version"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError(
                    f"{name} must be a non-empty string or explicit null (unknown)"
                )
        _require_str(self.evidence_ref, "evidence_ref")
        _require_digest(self.evidence_sha256, "evidence_sha256")
        if not isinstance(self.ce_verified, bool):
            raise ValueError("ce_verified must be an explicit bool")
        _require_source_kind(self.source_kind, "source_kind")


@dataclass(frozen=True, init=False)
class EndpointFindingAssociationV1:
    """One raw, body-verified reverse Endpoint-to-Finding association.

    ``finding_ids`` is the exact top-level ``findings`` list from a supported
    CE Endpoint detail response.  It is deliberately not a claim that each
    Finding has a uniquely attributable occurrence: shared host-only
    Endpoints remain ambiguous.  ``source_kind`` is an inert retained-byte
    origin label, never live-readback trust.
    """

    schema_version: int
    ce_release: str
    endpoint_id: int
    finding_ids: tuple
    evidence_ref: str
    evidence_sha256: str
    source_kind: str

    def __init__(self, *args, **kwargs):
        raise ValueError(
            "EndpointFindingAssociationV1 cannot be constructed directly; "
            "use parse_endpoint_detail to bind it to raw evidence"
        )

    @classmethod
    def _from_parsed(
        cls, *, schema_version: int, ce_release: str, endpoint_id: int,
        finding_ids: tuple, evidence_ref: str, evidence_sha256: str,
        source_kind: str,
    ) -> "EndpointFindingAssociationV1":
        obj = object.__new__(cls)
        for name, value in (
            ("schema_version", schema_version), ("ce_release", ce_release),
            ("endpoint_id", endpoint_id), ("finding_ids", finding_ids),
            ("evidence_ref", evidence_ref),
            ("evidence_sha256", evidence_sha256),
            ("source_kind", source_kind),
        ):
            object.__setattr__(obj, name, value)
        obj.__post_init__()
        return obj

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version!r}")
        _require_str(self.ce_release, "ce_release")
        _api_id(self.endpoint_id, "endpoint_id")
        if not isinstance(self.finding_ids, tuple):
            raise ValueError("finding_ids must be a tuple")
        for finding_id in self.finding_ids:
            _api_id(finding_id, "finding id")
        if len(set(self.finding_ids)) != len(self.finding_ids):
            raise ValueError("finding_ids must not contain duplicates")
        _require_str(self.evidence_ref, "evidence_ref")
        _require_digest(self.evidence_sha256, "evidence_sha256")
        _require_source_kind(self.source_kind, "source_kind")


@dataclass(frozen=True, init=False)
class EndpointIdentityV1:
    """Raw Endpoint detail proving response identity, not reverse membership.

    This DTO is used only when a supported Endpoint detail omits ``findings``.
    The exact Finding detail forward link carries the association; this DTO
    proves that the requested Endpoint was actually returned by CE.
    """

    schema_version: int
    ce_release: str
    endpoint_id: int
    evidence_ref: str
    evidence_sha256: str
    source_kind: str

    def __init__(self, *args, **kwargs):
        raise ValueError(
            "EndpointIdentityV1 cannot be constructed directly; use "
            "parse_endpoint_identity_detail to bind it to raw evidence"
        )

    @classmethod
    def _from_parsed(cls, *, schema_version: int, ce_release: str,
                     endpoint_id: int, evidence_ref: str,
                     evidence_sha256: str, source_kind: str):
        obj = object.__new__(cls)
        for name, value in (
            ("schema_version", schema_version), ("ce_release", ce_release),
            ("endpoint_id", endpoint_id), ("evidence_ref", evidence_ref),
            ("evidence_sha256", evidence_sha256), ("source_kind", source_kind),
        ):
            object.__setattr__(obj, name, value)
        obj.__post_init__()
        return obj

    def __post_init__(self):
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version!r}")
        _require_str(self.ce_release, "ce_release")
        _api_id(self.endpoint_id, "endpoint_id")
        _require_str(self.evidence_ref, "evidence_ref")
        _require_digest(self.evidence_sha256, "evidence_sha256")
        _require_source_kind(self.source_kind, "source_kind")


def parse_finding_detail(
    body_bytes: bytes,
    *,
    ce_release: str,
    requested_finding_id,
    requested_test_id,
    evidence_ref: str,
    evidence_sha256: str,
    source_kind: str,
) -> FindingDetailAssociationV1:
    """Parse and validate one supported-API Finding detail response.

    ``body_bytes`` is the exact raw read-back of
    ``GET /api/v2/findings/{id}/`` and the ONLY source of the parsed
    fields and the digest: there is no separate decoded-body input that
    could diverge from the bytes, so a caller cannot present fields
    parsed from one payload alongside another payload's retained bytes
    or digest. The bytes must decode to a JSON object with no duplicate
    keys: a conflicting or repeated object key is malformed, never
    silently resolved last-wins. The returned DTO
    is bound to the exact Finding requested: the response ``id`` must
    equal ``requested_finding_id`` and ``test`` must equal
    ``requested_test_id`` — a mismatch is malformed, not a relabelling,
    so a caller cannot use one Finding's read-back to claim another
    Finding's endpoints. ``evidence_sha256`` must be the sha256 hex
    digest of ``body_bytes``; a non-digest string or a mismatched digest
    is rejected, so an arbitrary ref or digest is never accepted as
    proof of the retained bytes. ``source_kind`` must be one of the
    bounded ``SOURCE_KINDS`` inert origin labels — never free-form
    trust or liveness language. The response's ``verified`` flag is
    CE's manual vulnerability verification and is carried as
    ``ce_verified`` only — it is never interpreted as read-back trust.
    This is an association projection only, not whole-object OpenAPI
    validation or artifact verification. ``evidence_ref`` is a
    caller-supplied label; only ``evidence_sha256`` is checked against the
    raw bytes. Malformed or partial read-backs raise ``ValueError``: they never
    yield a DTO that could be trusted. Unknown or missing
    ``component_name``/``component_version`` stay ``None`` (unknown);
    the description text is never read or mined for a port or occurrence
    identity.
    """
    if type(body_bytes) is not bytes:
        raise ValueError("body_bytes must be the raw read-back bytes")
    _require_digest(evidence_sha256, "evidence_sha256")
    actual_digest = hashlib.sha256(body_bytes).hexdigest()
    if actual_digest != evidence_sha256:
        raise ValueError(
            f"evidence_sha256 {evidence_sha256!r} does not match the sha256 "
            f"{actual_digest!r} of the raw read-back bytes; only the digest "
            "of the actual retained bytes is accepted as proof"
        )
    try:
        body = json.loads(
            body_bytes,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_json_constant,
        )
    except ValueError as exc:
        raise ValueError("body_bytes must decode to a JSON object") from exc
    if not isinstance(body, Mapping):
        raise ValueError("finding detail body must be a JSON object mapping")
    finding_id = _api_id(body.get("id"), "id")
    test_id = _api_id(body.get("test"), "test")
    _api_id(requested_finding_id, "requested_finding_id")
    _api_id(requested_test_id, "requested_test_id")
    if finding_id != requested_finding_id:
        raise ValueError(
            f"response id {finding_id} does not match the requested "
            f"Finding ID {requested_finding_id}; a mismatch is malformed, "
            "never relabelled"
        )
    if test_id != requested_test_id:
        raise ValueError(
            f"response test {test_id} does not match the requested "
            f"Test ID {requested_test_id}; a mismatch is malformed, "
            "never relabelled"
        )
    if "endpoints" not in body:
        raise ValueError(
            "'endpoints' is missing; missing and empty are distinct — an "
            "endpoint-less Finding reports an empty list"
        )
    endpoints = body["endpoints"]
    if not isinstance(endpoints, list):
        raise ValueError("'endpoints' must be a list of Endpoint IDs")
    endpoint_ids = tuple(_api_id(e, "endpoint id") for e in endpoints)
    if len(set(endpoint_ids)) != len(endpoint_ids):
        raise ValueError("'endpoints' contains duplicate IDs")
    for name in ("component_name", "component_version"):
        value = body.get(name)
        if value is not None and (not isinstance(value, str) or not value):
            raise ValueError(
                f"'{name}' must be a non-empty string or explicit null "
                "(unknown); other types are malformed"
            )
    if "verified" not in body:
        raise ValueError(
            "'verified' is missing; a partial read-back cannot yield a DTO"
        )
    ce_verified = body["verified"]
    if not isinstance(ce_verified, bool):
        raise ValueError(
            "'verified' must be an explicit boolean (CE manual "
            "vulnerability verification flag)"
        )
    _require_source_kind(source_kind, "source_kind")
    return FindingDetailAssociationV1._from_parsed(
        schema_version=SCHEMA_VERSION,
        ce_release=ce_release,
        test_id=test_id,
        finding_id=finding_id,
        endpoint_ids=endpoint_ids,
        component_name=body.get("component_name"),
        component_version=body.get("component_version"),
        evidence_ref=evidence_ref,
        evidence_sha256=evidence_sha256,
        ce_verified=ce_verified,
        source_kind=source_kind,
    )


def parse_endpoint_detail(
    body_bytes: bytes,
    *,
    ce_release: str,
    requested_endpoint_id,
    evidence_ref: str,
    evidence_sha256: str,
    source_kind: str,
) -> EndpointFindingAssociationV1:
    """Parse one supported CE Endpoint detail reverse-membership response.

    This is an association projection only, not whole-object OpenAPI
    validation or artifact verification. ``evidence_ref`` is a
    caller-supplied label; only ``evidence_sha256`` is checked against the
    raw bytes. Only the raw bytes supply the parsed fields. The response must be a JSON
    object with an integer ``id`` and a list of integer Finding IDs in the
    exact ``findings`` field.  Missing, duplicate, aliased or object-valued
    reverse shapes are malformed; no membership is inferred from any other
    field.  The requested Endpoint ID and SHA-256 digest must match the body.
    """
    if type(body_bytes) is not bytes:
        raise ValueError("body_bytes must be the raw read-back bytes")
    _require_digest(evidence_sha256, "evidence_sha256")
    actual_digest = hashlib.sha256(body_bytes).hexdigest()
    if actual_digest != evidence_sha256:
        raise ValueError(
            f"evidence_sha256 {evidence_sha256!r} does not match the sha256 "
            f"{actual_digest!r} of the raw read-back bytes"
        )
    try:
        body = json.loads(
            body_bytes,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_json_constant,
        )
    except ValueError as exc:
        raise ValueError("body_bytes must decode to a JSON object") from exc
    if not isinstance(body, Mapping):
        raise ValueError("endpoint detail body must be a JSON object mapping")
    endpoint_id = _api_id(body.get("id"), "id")
    _api_id(requested_endpoint_id, "requested_endpoint_id")
    if endpoint_id != requested_endpoint_id:
        raise ValueError(
            f"response id {endpoint_id} does not match the requested "
            f"Endpoint ID {requested_endpoint_id}; a mismatch is malformed"
        )
    if "findings" not in body:
        raise ValueError(
            "'findings' is missing; reverse Endpoint membership is incomplete"
        )
    findings = body["findings"]
    if not isinstance(findings, list):
        raise ValueError("'findings' must be a list of Finding IDs")
    finding_ids = tuple(_api_id(fid, "finding id") for fid in findings)
    if len(set(finding_ids)) != len(finding_ids):
        raise ValueError("'findings' contains duplicate IDs")
    _require_source_kind(source_kind, "source_kind")
    return EndpointFindingAssociationV1._from_parsed(
        schema_version=SCHEMA_VERSION, ce_release=ce_release,
        endpoint_id=endpoint_id, finding_ids=finding_ids,
        evidence_ref=evidence_ref, evidence_sha256=evidence_sha256,
        source_kind=source_kind,
    )


def parse_endpoint_identity_detail(
    body_bytes: bytes,
    *,
    ce_release: str,
    requested_endpoint_id,
    evidence_ref: str,
    evidence_sha256: str,
    source_kind: str,
) -> EndpointIdentityV1:
    """Validate raw Endpoint identity when CE omits reverse ``findings``.

    This parser proves only the exact Endpoint ID in the response. It does
    not create a Finding association; callers must obtain that edge from an
    exact Finding detail response.
    """
    if type(body_bytes) is not bytes:
        raise ValueError("body_bytes must be the raw read-back bytes")
    _require_digest(evidence_sha256, "evidence_sha256")
    if hashlib.sha256(body_bytes).hexdigest() != evidence_sha256:
        raise ValueError("evidence_sha256 does not match raw Endpoint detail bytes")
    try:
        body = json.loads(
            body_bytes,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_json_constant,
        )
    except ValueError as exc:
        raise ValueError("body_bytes must decode to a JSON object") from exc
    if not isinstance(body, Mapping):
        raise ValueError("Endpoint detail body must be a JSON object mapping")
    if "findings" in body:
        raise ValueError("Endpoint detail contains reverse membership; use parse_endpoint_detail")
    endpoint_id = _api_id(body.get("id"), "id")
    _api_id(requested_endpoint_id, "requested_endpoint_id")
    if endpoint_id != requested_endpoint_id:
        raise ValueError(
            f"response id {endpoint_id} does not match requested Endpoint ID "
            f"{requested_endpoint_id}"
        )
    _require_source_kind(source_kind, "source_kind")
    return EndpointIdentityV1._from_parsed(
        schema_version=SCHEMA_VERSION, ce_release=ce_release,
        endpoint_id=endpoint_id, evidence_ref=evidence_ref,
        evidence_sha256=evidence_sha256, source_kind=source_kind,
    )


def findings_readback_covers(pages, expected_finding_ids, requested_test_id):
    """Validate a retained test-filtered Findings list read-back.

    ``pages`` is the ordered sequence of list pages (each a mapping with
    ``count``, ``next`` and ``results``); ``expected_finding_ids`` is the
    expected complete set of Finding IDs for the filter;
    ``requested_test_id`` is the Test ID the list filter was made for.
    Returns ``(complete, reason)``: complete only when every page is
    well shaped, all pages agree on the reported ``count``, every item
    belongs to the requested Test ID (a mixed-Test list is never
    complete), the last page is the final page (no ``next``), the
    collected IDs are duplicate-free and exactly the expected set, and
    the collected total equals the agreed ``count``. This is shape and
    coverage validation for the retained read-back; it is never CR-04
    association proof.
    """
    if isinstance(pages, (str, bytes)) or not isinstance(pages, Sequence):
        return False, "pages must be a sequence of list pages"
    if not pages:
        return False, "pages must be a non-empty sequence of list pages"
    if isinstance(expected_finding_ids, (str, bytes)) or not isinstance(
        expected_finding_ids, Sequence
    ):
        return False, "expected_finding_ids must be a sequence of integers"
    expected = set()
    for fid in expected_finding_ids:
        if isinstance(fid, bool) or not isinstance(fid, int) or fid < 0:
            return False, "expected_finding_ids must be non-negative integers"
        expected.add(fid)
    if (
        isinstance(requested_test_id, bool)
        or not isinstance(requested_test_id, int)
        or requested_test_id < 0
    ):
        return False, "requested_test_id must be a non-negative integer"
    seen = set()
    agreed_count = None
    for index, page in enumerate(pages):
        if not isinstance(page, Mapping):
            return False, f"page {index} is not an object"
        results = page.get("results")
        if not isinstance(results, list):
            return False, f"page {index} has no list results"
        count = page.get("count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            return False, f"page {index} has no integer count"
        if agreed_count is None:
            agreed_count = count
        elif count != agreed_count:
            return False, "pages report disagreeing counts"
        for row in results:
            if not isinstance(row, Mapping):
                return False, f"page {index} has a malformed result row"
            test = row.get("test")
            if isinstance(test, bool) or not isinstance(test, int):
                return False, (
                    f"page {index} has a row without an integer test id"
                )
            if test != requested_test_id:
                return False, (
                    f"page {index} contains a Finding from a different "
                    f"Test; a mixed-Test list is never complete"
                )
            fid = row.get("id")
            if isinstance(fid, bool) or not isinstance(fid, int) or fid < 0:
                return False, f"page {index} has a row with a malformed finding id"
            if fid in seen:
                return False, f"finding id {fid} appears on more than one page"
            seen.add(fid)
        final = index == len(pages) - 1
        if final:
            if "next" not in page:
                return False, (
                    "final page is missing the required next key; a "
                    "missing next is not a null next and does not "
                    "satisfy coverage"
                )
            if page["next"] is not None:
                return False, "last page is not the final page"
        elif not (isinstance(page.get("next"), str) and page.get("next")):
            return False, (
                f"page {index} is not the final page but its next is not a "
                "non-empty link string; false, empty or a missing next "
                "cannot signal a continuation"
            )
        if final and len(seen) != agreed_count:
            return False, "collected finding ids do not match the reported count"
    if seen != expected:
        return False, "collected finding ids do not match the expected set"
    return True, "complete and count-covered"
