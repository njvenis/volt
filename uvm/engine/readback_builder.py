"""Operation-scoped, read-only DefectDojo CE read-back collection.

This module only composes the supported GET client and the association
parsers.  It does not settle an operation, write to CE, persist anything, or
claim live/artifact provenance.  Occurrence correspondence that cannot be
distinguished by the CE response remains pending.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from uvm.engine.association import (
    EndpointIdentityV1,
    EndpointFindingAssociationV1,
    FindingDetailAssociationV1,
    SOURCE_KINDS,
    findings_readback_covers,
    parse_endpoint_detail,
    parse_endpoint_identity_detail,
    parse_finding_detail,
)
from uvm.engine.ce_read_client import (
    CEReadClient, Collection, RawResponse, Resource, TransportError,
)
from uvm.engine.manifest import (
    DISPOSITION_INCLUDED,
    ManifestBindingRegistry,
    OccurrenceManifestV1,
)


class ReadbackError(ValueError):
    """The requested operation-scoped CE read-back is not complete."""


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReadbackError(f"{name} must be a non-empty string")
    return value


def _ce_id(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise ReadbackError(f"{name} must be a positive CE ID")
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and value.isdecimal() and int(value) > 0:
        return int(value)
    raise ReadbackError(f"{name} must be a positive CE ID")


def _raw_json(response: RawResponse, name: str) -> Mapping[str, Any]:
    try:
        value = json.loads(
            response.body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ReadbackError(f"{name} response is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ReadbackError(f"{name} response must be a JSON object")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject raw JSON objects with duplicate keys, including ``count``."""
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("JSON object contains duplicate keys")
    return dict(pairs)


def _reject_non_finite_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r} is not valid JSON")


def _digest(response: RawResponse) -> str:
    return hashlib.sha256(response.body).hexdigest()


def _operation_test_id(operation: Any, manifest: Any) -> int:
    values = []
    for owner, field in (
        (operation, "response_test_id"),
        (operation, "bound_test_id"),
        (operation, "test_id"),
        (manifest, "bound_test_id"),
    ):
        value = getattr(owner, field, None)
        if value is not None:
            values.append((field, _ce_id(value, field)))
    if not values:
        raise ReadbackError("operation and manifest have no requested or bound Test")
    ids = {value for _, value in values}
    if len(ids) != 1:
        raise ReadbackError("operation and manifest Test bindings disagree")
    return ids.pop()


def _validate_manifest(
    operation: Any,
    manifest: Any,
    manifest_registry: ManifestBindingRegistry,
) -> None:
    """Require a builder-issued V1 manifest and exact operation bindings."""
    if not isinstance(manifest, OccurrenceManifestV1):
        raise ReadbackError("manifest must be a builder-issued V1 manifest")
    if not isinstance(manifest_registry, ManifestBindingRegistry):
        raise ReadbackError(
            "manifest_registry must be the caller's shared binding registry"
        )
    registered = manifest_registry.for_operation(manifest.operation_id)
    if (
        registered is not manifest
        or registered.manifest_sha256 != manifest.manifest_sha256
    ):
        raise ReadbackError(
            "manifest is not the exact manifest pre-registered for this operation"
        )
    checks = (
        ("operation", manifest.operation_id, getattr(operation, "operation_id", None)),
        ("context", manifest.context_key, getattr(operation, "context_key", None)),
        ("run", manifest.run_id, getattr(operation, "source_run_id", None)),
        ("payload digest", manifest.payload_sha256, getattr(operation, "payload_sha256", None)),
    )
    for name, manifest_value, operation_value in checks:
        if manifest_value != operation_value:
            raise ReadbackError(f"manifest is bound to a different operation {name}")


def _included_count(manifest: OccurrenceManifestV1) -> int:
    return sum(
        1 for disposition in manifest.dispositions
        if disposition.disposition == DISPOSITION_INCLUDED
    )


@dataclass(frozen=True)
class ReadbackBundleV1:
    """Immutable measured raw read-back and parsed association bundle.

    ``mapping_status`` is deliberately always ``"pending"``: this slice
    measures CE links but does not resolve an occurrence or assert complete
    live-run/artifact coverage.
    """

    schema_version: int
    operation_id: str
    manifest_id: str
    context_key: str
    test_id: int
    test_response: RawResponse
    test_sha256: str
    finding_pages: tuple[RawResponse, ...]
    finding_page_sha256: tuple[str, ...]
    finding_ids: tuple[int, ...]
    finding_details: tuple[RawResponse, ...]
    finding_detail_sha256: tuple[str, ...]
    finding_associations: tuple[FindingDetailAssociationV1, ...]
    endpoint_ids: tuple[int, ...]
    endpoint_details: tuple[RawResponse, ...]
    endpoint_detail_sha256: tuple[str, ...]
    endpoint_associations: tuple[
        EndpointFindingAssociationV1 | EndpointIdentityV1, ...
    ]
    mapping_status: str = "pending"

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ReadbackError("unsupported ReadbackBundleV1 schema_version")
        if self.mapping_status != "pending":
            raise ReadbackError("ReadbackBundleV1 mapping_status must be 'pending'")
        if not isinstance(self.test_response, RawResponse):
            raise ReadbackError("test_response must be a RawResponse")
        if self.test_sha256 != _digest(self.test_response):
            raise ReadbackError("test_sha256 does not match test_response")
        digest_pairs = (
            (self.finding_pages, self.finding_page_sha256, "finding page"),
            (self.finding_details, self.finding_detail_sha256, "finding detail"),
            (self.endpoint_details, self.endpoint_detail_sha256, "endpoint detail"),
        )
        for responses, digests, label in digest_pairs:
            if len(responses) != len(digests):
                raise ReadbackError(f"{label} response/digest lengths differ")
            for response, digest in zip(responses, digests):
                if not isinstance(response, RawResponse) or digest != _digest(response):
                    raise ReadbackError(f"{label} digest does not match raw response")


def build_readback(
    client: Any,
    operation: Any,
    manifest: Any,
    *,
    ce_release: str,
    evidence_ref: str,
    source_kind: str,
    engagement_id: int | None = None,
    manifest_registry: ManifestBindingRegistry | None = None,
    expected_ce_base_url: str | None = None,
) -> ReadbackBundleV1:
    """Collect one complete, operation/manifest/Test-scoped CE read-back.

    ``client`` must be a supported ``CEReadClient``-compatible reader.  The
    evidence reference and source label are caller inputs only; neither is
    upgraded into provenance or verification by this function.
    ``manifest_registry`` must be the shared, authoritative registry already
    bound for this operation; this in-memory registry is not durable proof.
    """
    _text(ce_release, "ce_release")
    if expected_ce_base_url is not None:
        if (not isinstance(expected_ce_base_url, str)
                or not expected_ce_base_url
                or getattr(client, "base_url", None) != expected_ce_base_url.rstrip("/")):
            raise ReadbackError(
                "CE read client does not match the verified deployment URL"
            )
    operation_engine_release = _text(
        getattr(operation, "engine_release", None), "operation.engine_release"
    )
    if ce_release != operation_engine_release:
        raise ReadbackError("ce_release must exactly match operation.engine_release")
    _text(evidence_ref, "evidence_ref")
    if type(source_kind) is not str or source_kind not in SOURCE_KINDS:
        raise ReadbackError(f"source_kind must be one of {SOURCE_KINDS!r}")
    operation_id = _text(getattr(operation, "operation_id", None), "operation_id")
    manifest_id = _text(getattr(manifest, "manifest_id", None), "manifest_id")
    if manifest_registry is None:
        raise ReadbackError("manifest_registry is required for operation binding")
    _validate_manifest(operation, manifest, manifest_registry)
    if getattr(manifest, "operation_id", None) != operation_id:
        raise ReadbackError("manifest is bound to a different operation")
    context_key = _text(getattr(operation, "context_key", None), "context_key")
    if getattr(manifest, "context_key", None) != context_key:
        raise ReadbackError("manifest is bound to a different context")
    test_id = _operation_test_id(operation, manifest)
    expected_engagement_id = _ce_id(engagement_id, "engagement_id")

    test = client.get_test(test_id, engagement_id=expected_engagement_id)
    if not isinstance(test, Resource):
        raise ReadbackError("get_test did not return a CE Resource")
    test_body = _raw_json(test.response, "Test")
    if _ce_id(test_body.get("id"), "Test id") != test_id:
        raise ReadbackError("Test detail is outside the requested scope")

    collection = client.list_findings(test_id=test_id)
    if not isinstance(collection, Collection):
        raise ReadbackError("list_findings did not return a CE Collection")
    expected_ids = tuple(_ce_id(item.get("id"), "Finding id") for item in collection.items)
    pages = tuple(_raw_json(page, "Finding collection") for page in collection.pages)
    complete, reason = findings_readback_covers(pages, expected_ids, test_id)
    if not complete:
        raise ReadbackError(f"Finding collection is incomplete: {reason}")
    if len(set(expected_ids)) != len(expected_ids):
        raise ReadbackError("Finding collection contains duplicate IDs")
    included = _included_count(manifest)
    if (included > 0 and not expected_ids) or (included == 0 and expected_ids):
        raise ReadbackError(
            "included manifest disposition and Finding read-back coverage disagree"
        )

    finding_responses = tuple(client.get_finding(fid, test_id=test_id) for fid in expected_ids)
    finding_details = tuple(
        parse_finding_detail(
            resource.response.body,
            ce_release=ce_release,
            requested_finding_id=fid,
            requested_test_id=test_id,
            evidence_ref=evidence_ref,
            evidence_sha256=_digest(resource.response),
            source_kind=source_kind,
        )
        for fid, resource in zip(expected_ids, finding_responses)
    )
    endpoint_ids = tuple(sorted({endpoint_id for detail in finding_details for endpoint_id in detail.endpoint_ids}))
    endpoint_responses = tuple(client.get_endpoint(endpoint_id) for endpoint_id in endpoint_ids)
    endpoint_details = []
    for endpoint_id, resource in zip(endpoint_ids, endpoint_responses):
        endpoint_body = _raw_json(resource.response, "Endpoint detail")
        parser = (parse_endpoint_detail if "findings" in endpoint_body
                  else parse_endpoint_identity_detail)
        endpoint_details.append(parser(
            resource.response.body,
            ce_release=ce_release,
            requested_endpoint_id=endpoint_id,
            evidence_ref=evidence_ref,
            evidence_sha256=_digest(resource.response),
            source_kind=source_kind,
        ))
    endpoint_details = tuple(endpoint_details)

    forward = {detail.finding_id: set(detail.endpoint_ids) for detail in finding_details}
    endpoint_scope = {detail.endpoint_id for detail in endpoint_details}
    reverse = {detail.endpoint_id: set(detail.finding_ids)
               for detail in endpoint_details
               if isinstance(detail, EndpointFindingAssociationV1)}
    finding_set = set(expected_ids)
    if endpoint_scope != set(endpoint_ids):
        raise ReadbackError("Endpoint detail scope is missing or extra")
    if any(ids - finding_set for ids in reverse.values()):
        raise ReadbackError("Endpoint reverse link contains an extra Finding")
    for finding_id, linked_endpoints in forward.items():
        for endpoint_id in linked_endpoints:
            if (endpoint_id in reverse
                    and finding_id not in reverse[endpoint_id]):
                raise ReadbackError("Finding/Endpoint links are asymmetric")
    for endpoint_id, linked_findings in reverse.items():
        for finding_id in linked_findings:
            if endpoint_id not in forward.get(finding_id, set()):
                raise ReadbackError("Endpoint/Finding links are asymmetric")

    return ReadbackBundleV1(
        schema_version=1,
        operation_id=operation_id,
        manifest_id=manifest_id,
        context_key=context_key,
        test_id=test_id,
        test_response=test.response,
        test_sha256=_digest(test.response),
        finding_pages=collection.pages,
        finding_page_sha256=tuple(_digest(page) for page in collection.pages),
        finding_ids=expected_ids,
        finding_details=tuple(resource.response for resource in finding_responses),
        finding_detail_sha256=tuple(_digest(resource.response) for resource in finding_responses),
        finding_associations=finding_details,
        endpoint_ids=endpoint_ids,
        endpoint_details=tuple(resource.response for resource in endpoint_responses),
        endpoint_detail_sha256=tuple(_digest(resource.response) for resource in endpoint_responses),
        endpoint_associations=endpoint_details,
    )


def validate_readback_bundle(
    readback: ReadbackBundleV1,
    operation: Any,
    manifest: Any,
    *,
    ce_release: str,
    expected_ce_base_url: str,
    engagement_id: int,
) -> ReadbackBundleV1:
    """Rebuild a supplied bundle from its exact raw responses and verify it.

    The replay client only serves the URLs generated by ``build_readback``
    from the durable CE base URL. Missing pages, foreign origins, changed
    routes, and altered parsed DTO projections therefore fail before a
    settlement write can begin.
    """
    if not isinstance(readback, ReadbackBundleV1):
        raise ReadbackError("settlement requires a complete ReadbackBundleV1")
    all_responses = (
        readback.test_response,
        *readback.finding_pages,
        *readback.finding_details,
        *readback.endpoint_details,
    )
    retained_by_url: dict[str, RawResponse] = {}
    for response in all_responses:
        if not isinstance(response, RawResponse):
            raise ReadbackError("read-back contains a non-RawResponse value")
        if response.url in retained_by_url:
            raise ReadbackError("read-back repeats a raw response URL")
        retained_by_url[response.url] = response

    if not readback.finding_associations:
        raise ReadbackError("read-back has no parsed Finding evidence")
    source = readback.finding_associations[0]
    replayed = rebuild_readback_from_responses(
        all_responses, operation, manifest,
        ce_release=ce_release,
        expected_ce_base_url=expected_ce_base_url,
        engagement_id=engagement_id,
        evidence_ref=source.evidence_ref,
        source_kind=source.source_kind,
    )
    if replayed != readback:
        raise ReadbackError(
            "read-back parsed fields or summary IDs disagree with retained raw responses"
        )
    return replayed


def rebuild_readback_from_responses(
    responses: tuple[RawResponse, ...] | list[RawResponse],
    operation: Any,
    manifest: Any,
    *,
    ce_release: str,
    expected_ce_base_url: str,
    engagement_id: int,
    evidence_ref: str,
    source_kind: str,
) -> ReadbackBundleV1:
    """Reconstruct all parsed read-back fields from retained response bytes."""
    retained_by_url: dict[str, RawResponse] = {}
    for response in responses:
        if not isinstance(response, RawResponse):
            raise ReadbackError("read-back contains a non-RawResponse value")
        if response.url in retained_by_url:
            raise ReadbackError("read-back repeats a raw response URL")
        retained_by_url[response.url] = response

    def replay(method, url, headers, timeout, *, follow_redirects):
        if method != "GET" or follow_redirects:
            raise ReadbackError("read-back replay permits supported GETs only")
        response = retained_by_url.get(url)
        if response is None:
            raise TransportError(
                "read-back raw bytes do not cover the configured deployment route"
            )
        return response

    registry = ManifestBindingRegistry()
    registry._bind_verified_durable(manifest)
    replayed = build_readback(
        CEReadClient(expected_ce_base_url, replay), operation, manifest,
        ce_release=ce_release, evidence_ref=evidence_ref,
        source_kind=source_kind,
        engagement_id=engagement_id,
        manifest_registry=registry,
        expected_ce_base_url=expected_ce_base_url,
    )
    used_responses = (
        replayed.test_response, *replayed.finding_pages,
        *replayed.finding_details, *replayed.endpoint_details,
    )
    if {item.url for item in used_responses} != set(retained_by_url):
        raise ReadbackError("read-back contains missing or extra raw response routes")
    return replayed


collect_readback = build_readback

__all__ = [
    "ReadbackError", "ReadbackBundleV1", "build_readback", "collect_readback",
    "validate_readback_bundle", "rebuild_readback_from_responses",
]
