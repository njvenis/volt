"""Offline proof for the bounded Qualys Generic Findings prototype."""

from __future__ import annotations

import json
import hashlib
import importlib.util
import unittest
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

from uvm.engine.qualys_generic_adapter import (
    DEDUPLICATION_ALGORITHM,
    SCAN_TYPE,
    V3_FEATURE_LOCATIONS,
    QualysAdapterError,
    build_generic_import,
)

ROOT = Path(__file__).parents[2]
FIXTURE = ROOT / "tests/fixtures/g1/qualys-3x2.xml"
GENERATOR = ROOT / "tests/fixtures/g1/generic-occurrence-prototype/provenance-v1/generate_bundle.py"
spec = importlib.util.spec_from_file_location("g1_fixture_generator", GENERATOR)
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)
build_source_observations = generator.build_source_observations


def independent_source_expectation(xml_bytes: bytes) -> list[tuple[str, str, int, str]]:
    """Test oracle: deliberately independent from adapter row objects/IDs."""
    root = ElementTree.fromstring(xml_bytes)
    result = []
    for host in root.findall("./HOST_LIST/HOST"):
        hostname = (host.findtext("DNS") or host.findtext("IP") or "").strip()
        for vuln in host.findall("./VULN_INFO_LIST/VULN_INFO"):
            result.append((
                vuln.findtext("QID", "").strip(), hostname,
                int(vuln.findtext("PORT", "0")),
                vuln.findtext("COMPONENT_NAME", "").strip(),
            ))
    return sorted(result)


class QualysGenericAdapterTest(unittest.TestCase):
    def test_exact_six_rows_and_source_derived_locators(self) -> None:
        source = FIXTURE.read_bytes()
        imported = build_generic_import(source)
        body = json.loads(imported.payload)
        self.assertEqual(imported.scan_type, SCAN_TYPE)
        self.assertEqual(imported.scan_type, "Generic Findings Import")
        self.assertEqual(set(body), {"findings"})
        self.assertNotIn("type", body)
        self.assertEqual(imported.deduplication_algorithm, DEDUPLICATION_ALGORITHM)
        self.assertFalse(imported.v3_feature_locations)
        findings = body["findings"]
        self.assertEqual(len(findings), 6)
        required = {"title", "severity", "description"}
        self.assertTrue(all(required <= set(item) for item in findings))
        self.assertTrue(all("name" not in item for item in findings))
        actual = sorted((item["vuln_id_from_tool"], item["endpoints"][0]["host"],
                         item["endpoints"][0]["port"], item["component_name"])
                        for item in findings)
        self.assertEqual(actual, independent_source_expectation(source))
        self.assertEqual(len({item["unique_id_from_tool"] for item in findings}), 6)
        self.assertTrue(all(item["unique_id_from_tool"].startswith("uvm:qualys:occurrence:") for item in findings))

    def test_identity_is_stable_when_rows_are_reordered(self) -> None:
        source = FIXTURE.read_bytes()
        root = ElementTree.fromstring(source)
        host_list = root.find("HOST_LIST")
        assert host_list is not None
        hosts = list(host_list)
        host_list[:] = list(reversed(hosts))
        reordered = ElementTree.tostring(root, encoding="utf-8")
        self.assertEqual(build_generic_import(source).payload, build_generic_import(reordered).payload)

    def test_duplicate_identity_is_rejected(self) -> None:
        source = FIXTURE.read_bytes().replace(
            b"<QID id=\"qid-1001\">1001</QID><TYPE>Vuln</TYPE><PORT>443</PORT>",
            b"<QID id=\"qid-1001\">1001</QID><TYPE>Vuln</TYPE><PORT>443</PORT>", 1)
        root = ElementTree.fromstring(source)
        vuln = root.find(".//VULN_INFO")
        assert vuln is not None
        parent = root.find(".//VULN_INFO_LIST")
        assert parent is not None
        parent.append(vuln)
        with self.assertRaises(QualysAdapterError):
            build_generic_import(ElementTree.tostring(root, encoding="utf-8"))

    def test_removed_row_changes_exact_payload(self) -> None:
        source = FIXTURE.read_bytes()
        root = ElementTree.fromstring(source)
        row = root.find(".//VULN_INFO")
        assert row is not None
        parent = root.find(".//VULN_INFO_LIST")
        assert parent is not None
        parent.remove(row)
        reduced = build_generic_import(ElementTree.tostring(root, encoding="utf-8"))
        self.assertEqual(len(json.loads(reduced.payload)["findings"]), 5)
        self.assertNotEqual(reduced.payload, build_generic_import(source).payload)

    def test_swapped_id_is_detected_by_independent_membership_check(self) -> None:
        imported = build_generic_import(FIXTURE.read_bytes())
        body = json.loads(imported.payload)["findings"]
        original = {
            (item["vuln_id_from_tool"], item["endpoints"][0]["host"],
             item["endpoints"][0]["port"], item["component_name"]): item["unique_id_from_tool"]
            for item in body
        }
        body[0]["unique_id_from_tool"], body[1]["unique_id_from_tool"] = (
            body[1]["unique_id_from_tool"], body[0]["unique_id_from_tool"])
        observed = {(item["vuln_id_from_tool"], item["endpoints"][0]["host"],
                     item["endpoints"][0]["port"], item["component_name"]): item["unique_id_from_tool"]
                    for item in body}
        self.assertNotEqual(observed, original)

    def test_repeat_preserves_identity_but_uses_last_found_for_generic_date(self) -> None:
        source = FIXTURE.read_bytes().replace(
            b"<SEVERITY>High</SEVERITY>", b"<SEVERITY>Critical</SEVERITY>", 1)
        source = source.replace(
            b"<RESULT>A</RESULT>",
            b"<RESULT>A</RESULT><FIRST_FOUND>2026-08-01T00:00:00Z</FIRST_FOUND>"
            b"<LAST_FOUND>2026-09-25T00:00:00Z</LAST_FOUND>", 1)
        first = build_generic_import(FIXTURE.read_bytes())
        repeat = build_generic_import(source)
        before = {row.source_identity: row for row in first.rows}
        after = {row.source_identity: row for row in repeat.rows}
        self.assertEqual(set(before), set(after))
        changed = next(row for row in repeat.rows if row.result == "A")
        self.assertEqual(changed.severity, "Critical")
        self.assertEqual(changed.generic_date, "2026-09-25")
        body = json.loads(repeat.payload)
        record = next(item for item in body["findings"] if item["description"] == "A")
        self.assertEqual(record["severity"], "Critical")
        self.assertEqual(record["date"], "2026-09-25")

    def test_first_found_alone_does_not_become_generic_date(self) -> None:
        source = FIXTURE.read_bytes().replace(
            b"<RESULT>A</RESULT>",
            b"<RESULT>A</RESULT><FIRST_FOUND>2026-08-01T00:00:00Z</FIRST_FOUND>", 1)
        record = next(item for item in json.loads(build_generic_import(source).payload)["findings"]
                      if item["description"] == "A")
        self.assertNotIn("date", record)

    def test_invalid_or_timezone_less_source_date_is_rejected(self) -> None:
        source = FIXTURE.read_bytes().replace(
            b"<RESULT>A</RESULT>",
            b"<RESULT>A</RESULT><LAST_FOUND>2026-09-25</LAST_FOUND>", 1)
        with self.assertRaises(QualysAdapterError):
            build_generic_import(source)

    def test_source_observations_keep_collection_and_scanner_times_distinct(self) -> None:
        source = FIXTURE.read_bytes().replace(
            b"<RESULT>A</RESULT>",
            b"<RESULT>A</RESULT><FIRST_FOUND>2026-08-01T00:00:00Z</FIRST_FOUND>"
            b"<LAST_FOUND>2026-09-25T00:00:00Z</LAST_FOUND>", 1)
        observations = build_source_observations(
            source, source_account_id="qualys-account", run_id="run-1",
            collected_at=datetime(2026, 9, 29, tzinfo=timezone.utc),
            raw_evidence_ref="fixture://repeat",
            raw_evidence_sha256=hashlib.sha256(source).hexdigest(),
        )
        observed = next(item for item in observations if item.source_first_seen_at is not None)
        self.assertEqual(observed.observed_at.isoformat(), "2026-09-25T00:00:00+00:00")
        self.assertEqual(observed.source_first_seen_at.isoformat(), "2026-08-01T00:00:00+00:00")
        self.assertNotEqual(observed.observed_at, observed.collected_at)
        self.assertIsNone(observed.occurrence_id)

    def test_source_observations_reject_unverified_digest(self) -> None:
        source = FIXTURE.read_bytes()
        with self.assertRaises(ValueError):
            build_source_observations(
                source, source_account_id="qualys-account", run_id="run-1",
                collected_at=datetime(2026, 9, 29, tzinfo=timezone.utc),
                raw_evidence_ref="fixture://base", raw_evidence_sha256="0" * 64)


if __name__ == "__main__":
    unittest.main()
