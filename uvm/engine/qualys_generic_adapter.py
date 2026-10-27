"""Qualys XML to Generic Findings Import prototype.

This is a pure, versioned G1 experiment.  It does not call DefectDojo or
write UVM state.  The caller retains the source XML and the returned bytes as
the operation evidence before posting them through the supported import API.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final
from xml.etree import ElementTree

SCAN_TYPE: Final = "Generic Findings Import"
PARSER_CONFIG_VERSION: Final = "uvm-qualys-generic-v1"
DEDUPLICATION_ALGORITHM: Final = "unique_id_from_tool"
V3_FEATURE_LOCATIONS: Final = False


class QualysAdapterError(ValueError):
    """The source cannot be converted without guessing or losing identity."""


@dataclass(frozen=True)
class QualysRow:
    qid: str
    host: str
    port: int
    component_name: str
    component_version: str
    title: str
    severity: str
    result: str
    source_identity: str
    first_found: datetime | None = None
    last_found: datetime | None = None

    @property
    def generic_date(self) -> str | None:
        """The pinned Generic Findings date policy: LAST_FOUND wins.

        The source observation timestamp remains distinct; this is only the
        parser-facing field sent to CE. ``FIRST_FOUND`` alone never becomes
        the Generic date, and collection time is never substituted.
        """
        return self.last_found.date().isoformat() if self.last_found else None


@dataclass(frozen=True)
class GenericImport:
    scan_type: str
    parser_config_version: str
    deduplication_algorithm: str
    v3_feature_locations: bool
    rows: tuple[QualysRow, ...]
    payload: bytes


def _optional_instant(element: ElementTree.Element, name: str) -> datetime | None:
    value = element.findtext(name)
    if value is None or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise QualysAdapterError(f"invalid {name} timestamp {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise QualysAdapterError(f"{name} timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _text(element: ElementTree.Element, name: str, *, required: bool = True) -> str:
    value = element.findtext(name)
    if value is None or not value.strip():
        if required:
            raise QualysAdapterError(f"missing {name} in VULN_INFO")
        return ""
    return value.strip()


def _stable_id(qid: str, host: str, port: int, component: str, version: str) -> str:
    # Length-prefixed fields avoid delimiter ambiguity.  No row index, source
    # order, timestamp, or caller/run identifier is included.
    fields = (qid, host, str(port), component, version)
    canonical = "".join(f"{len(value)}:{value}" for value in fields).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    return f"uvm:qualys:occurrence:{digest}"


def parse_qualys_rows(xml_bytes: bytes) -> tuple[QualysRow, ...]:
    """Parse included Qualys rows and reject ambiguous/unsupported input."""
    try:
        root = ElementTree.fromstring(xml_bytes)
    except ElementTree.ParseError as exc:
        raise QualysAdapterError("invalid Qualys XML") from exc

    rows: list[QualysRow] = []
    for host_element in root.findall("./HOST_LIST/HOST"):
        host = _text(host_element, "DNS", required=False) or _text(host_element, "IP")
        for vuln in host_element.findall("./VULN_INFO_LIST/VULN_INFO"):
            qid = _text(vuln, "QID")
            port_text = _text(vuln, "PORT")
            try:
                port = int(port_text)
            except ValueError as exc:
                raise QualysAdapterError(f"non-numeric port {port_text!r}") from exc
            if not 1 <= port <= 65535:
                raise QualysAdapterError(f"port out of range: {port}")
            component = _text(vuln, "COMPONENT_NAME")
            version = _text(vuln, "COMPONENT_VERSION", required=False)
            row_id = _stable_id(qid, host, port, component, version)
            rows.append(QualysRow(
                qid=qid,
                host=host,
                port=port,
                component_name=component,
                component_version=version,
                title=_text(vuln, "TITLE"),
                severity=_text(vuln, "SEVERITY"),
                result=_text(vuln, "RESULT", required=False),
                source_identity=row_id,
                first_found=_optional_instant(vuln, "FIRST_FOUND"),
                last_found=_optional_instant(vuln, "LAST_FOUND"),
            ))

    if not rows:
        raise QualysAdapterError("Qualys XML contains no supported VULN_INFO rows")
    ids = [row.source_identity for row in rows]
    if len(ids) != len(set(ids)):
        raise QualysAdapterError("duplicate source identity; refusing ambiguous import")
    return tuple(sorted(rows, key=lambda row: row.source_identity))


def build_generic_import(xml_bytes: bytes) -> GenericImport:
    """Return exact JSON bytes for the supported Generic Findings parser."""
    rows = parse_qualys_rows(xml_bytes)
    findings = [
        {
            "component_name": row.component_name,
            "component_version": row.component_version,
            "description": row.result,
            "endpoints": [{"host": row.host, "port": row.port}],
            "title": row.title,
            "severity": row.severity,
            "unique_id_from_tool": row.source_identity,
            "vuln_id_from_tool": row.qid,
            **({"date": row.generic_date} if row.generic_date is not None else {}),
        }
        for row in rows
    ]
    payload = json.dumps({"findings": findings}, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return GenericImport(
        scan_type=SCAN_TYPE,
        parser_config_version=PARSER_CONFIG_VERSION,
        deduplication_algorithm=DEDUPLICATION_ALGORITHM,
        v3_feature_locations=V3_FEATURE_LOCATIONS,
        rows=rows,
        payload=payload,
    )
