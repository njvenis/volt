"""Bind complete CE read-back Findings to retained included occurrences."""

from __future__ import annotations

import json
from dataclasses import dataclass

from uvm.engine.manifest import DISPOSITION_INCLUDED, OccurrenceManifestV1
from uvm.engine.readback_builder import ReadbackBundleV1, ReadbackError


@dataclass(frozen=True)
class OccurrenceFindingLinkV1:
    occurrence_id: str
    finding_id: int
    endpoint_id: int | None
    component_name: str | None
    component_version: str | None


def _object_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ReadbackError("Finding read-back contains duplicate JSON keys")
        value[key] = item
    return value


def build_occurrence_finding_links(
    manifest: OccurrenceManifestV1,
    readback: ReadbackBundleV1,
) -> tuple[OccurrenceFindingLinkV1, ...]:
    """Require exact payload-record identity matches for all included rows.

    The CE Finding's exact native ``unique_id_from_tool`` is preferred; for
    scanners which expose their native key as ``vuln_id_from_tool`` instead,
    that exact field is accepted. The resulting key is compared to the
    operation's immutable ``PayloadRecordV1.payload_record_id``. The
    manifest's explicit source-observation membership then identifies the
    retained UVM occurrence(s) represented by that payload record.  No title,
    CVE, host, description, or display-name similarity is used.
    """
    if not isinstance(manifest, OccurrenceManifestV1):
        raise ReadbackError("manifest must be OccurrenceManifestV1")
    if not isinstance(readback, ReadbackBundleV1):
        raise ReadbackError("readback must be a complete ReadbackBundleV1")
    if (readback.operation_id != manifest.operation_id
            or readback.manifest_id != manifest.manifest_id
            or readback.context_key != manifest.context_key):
        raise ReadbackError("read-back and manifest operation bindings disagree")
    finding_rows = {}
    for response, detail in zip(readback.finding_details,
                                readback.finding_associations):
        try:
            body = json.loads(response.body.decode("utf-8"),
                              object_pairs_hook=_object_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ReadbackError("Finding detail bytes are malformed") from exc
        if not isinstance(body, dict):
            raise ReadbackError("Finding detail must be a JSON object")
        record_id = body.get("unique_id_from_tool")
        if record_id is None:
            record_id = body.get("vuln_id_from_tool")
        if not isinstance(record_id, str) or not record_id:
            raise ReadbackError(
                "Finding detail lacks the exact unique_id_from_tool needed for occurrence association"
            )
        finding_rows.setdefault(record_id, []).append(detail)

    included = {
        disposition.observation_id: disposition.occurrence_id
        for disposition in manifest.dispositions
        if disposition.disposition == DISPOSITION_INCLUDED
    }
    links: list[OccurrenceFindingLinkV1] = []
    matched_records: set[str] = set()
    for payload_record in manifest.payload_records:
        occurrences = tuple(
            included[observation_id]
            for observation_id in payload_record.source_observation_ids
            if observation_id in included
        )
        if not occurrences:
            continue
        matches = finding_rows.get(payload_record.payload_record_id, ())
        if not matches:
            raise ReadbackError(
                f"included payload record {payload_record.payload_record_id!r} has no CE Finding"
            )
        if payload_record.payload_record_id in matched_records:
            raise ReadbackError("one CE unique ID is assigned to multiple payload records")
        matched_records.add(payload_record.payload_record_id)
        for detail in matches:
            for occurrence_id in occurrences:
                endpoints = detail.endpoint_ids or (None,)
                for endpoint_id in endpoints:
                    links.append(OccurrenceFindingLinkV1(
                        occurrence_id=occurrence_id,
                        finding_id=detail.finding_id,
                        endpoint_id=endpoint_id,
                        component_name=detail.component_name,
                        component_version=detail.component_version,
                    ))
    if included:
        linked = {link.occurrence_id for link in links}
        missing = set(included.values()) - linked
        if missing:
            raise ReadbackError(
                f"complete Finding read-back has no association for {len(missing)} included occurrence(s)"
            )
    if len(links) != len(set(links)):
        raise ReadbackError("occurrence read-back produced duplicate links")
    return tuple(sorted(links, key=lambda item: (
        item.occurrence_id, item.finding_id,
        -1 if item.endpoint_id is None else item.endpoint_id,
        item.component_name or "", item.component_version or "",
    )))
