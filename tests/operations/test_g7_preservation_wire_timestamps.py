import copy
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest

from uvm.operations.preservation import _class_wire, _valid_class_dto, utc_timestamp
from uvm.operations.preservation_api import _record_item, _run_dto

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/g7-preservation"


class PreservationWireTimestampTests(unittest.TestCase):
    def test_datetime_and_offset_string_normalize_to_z_without_losing_fraction(self):
        value = "2026-10-28T19:22:46.359284+00:00"
        expected = "2026-10-28T19:22:46.359284Z"
        self.assertEqual(utc_timestamp(value), expected)
        self.assertEqual(utc_timestamp(datetime.fromisoformat(value)), expected)
        self.assertEqual(utc_timestamp("2026-10-28T20:22:46.359284+01:00"), expected)
        self.assertEqual(utc_timestamp("2026-10-28T19:22:46.000000+00:00"),
            "2026-10-28T19:22:46.000000Z")
        self.assertEqual(utc_timestamp("2026-10-28T19:22:46Z"), "2026-10-28T19:22:46Z")
        with self.assertRaises(ValueError):
            utc_timestamp("2026-10-28T19:22:46.359284")

    def test_record_projection_normalizes_aware_legacy_offset(self):
        member = {"record_key":"observation:test", "record_kind":"observation",
            "retained_at":"2026-10-28T19:22:46.359284+00:00", "state":"verified",
            "reasons":[], "expected_sha256":"a"*64, "actual_sha256":"a"*64,
            "record_sha256":"b"*64, "byte_bearing":True,
            "evidence_id":"00000000-0000-4000-8000-000000000001"}
        item = _record_item(member, "product.source_evidence", True)
        self.assertEqual(item["retained_at"], "2026-10-28T19:22:46.359284Z")

    def test_historical_run_revision_serializes_all_timestamp_fields_as_utc_z(self):
        instant = datetime.fromisoformat("2026-10-28T20:22:46.359284+01:00")
        run = {"run_id":"00000000-0000-4000-8000-000000000001", "revision":1,
            "source_family":"fixture", "source_account_id":"account", "scope_key":"scope",
            "expected_run_id":None, "manual_origin":"operator", "schedule_id":None,
            "schedule_revision":None, "source_report_id":None, "expected_at":instant,
            "started_at":instant, "ended_at":None, "state":"complete",
            "retrieval_status":"complete", "retrieval_reasons":[], "coverage_status":"complete",
            "coverage_reasons":[], "freshness_status":"current", "freshness_reasons":[],
            "created_at":instant}
        attempt = {"attempt_no":1, "started_at":instant, "finished_at":instant,
            "response_class":"200", "success":True, "retry_after_microseconds":None,
            "error_code":None}
        page = {"ordinal":1, "cursor":None, "page_ref":"page-id", "attempt_no":1,
            "response_class":"200", "record_count":0, "next_cursor":None,
            "is_terminal":True, "failed":False, "request_identity":"request",
            "report_id":None, "query_scope":"scope", "evidence_ref":None}
        evidence = {"evidence_id":"00000000-0000-4000-8000-000000000002", "schema_version":1,
            "evidence_ref":"evidence", "sha256":"a"*64, "kind":"page", "registered_at":instant}
        transition = {"revision":1, "state":"complete", "run_revision":1,
            "effective_at":instant, "recorded_at":instant}
        dto = _run_dto(run, [attempt], [page], [evidence], [transition], None, b"k"*32)
        timestamps = [dto["expected_at"], dto["started_at"], dto["created_at"],
            dto["attempts"][0]["started_at"], dto["attempts"][0]["finished_at"],
            dto["evidence"][0]["registered_at"], dto["expected_transitions"][0]["effective_at"],
            dto["expected_transitions"][0]["recorded_at"]]
        self.assertEqual(set(timestamps), {"2026-10-28T19:22:46.359284Z"})

    def test_actual_summary_is_normalized_and_accepted_by_current_ui_parser(self):
        summary = json.loads((FIXTURES / "summary-actual-v1.json").read_text())
        summary["classes"] = [_class_wire(item) for item in summary["classes"]]
        for item in summary["classes"]:
            self.assertTrue(_valid_class_dto(item, item["class_id"]))
        page = json.loads((FIXTURES / "source-record-page-actual-v1.json").read_text())
        page["items"] = [_record_item({**item, "byte_bearing": item["expected_sha256"] is not None
            or item["actual_sha256"] is not None,
            "evidence_id": item["readback_url"].rsplit("/", 1)[-1] if item["readback_url"] else None},
            page["class_id"], True) for item in page["items"]]
        with tempfile.TemporaryDirectory() as directory:
            normalized_summary = Path(directory) / "summary.json"
            normalized_page = Path(directory) / "page.json"
            normalized_summary.write_text(json.dumps(summary))
            normalized_page.write_text(json.dumps(page))
            result = subprocess.run(["node", str(ROOT / "tools/g7_preservation_ui_timestamp_regression.mjs"),
                str(FIXTURES / "summary-actual-v1.json"), str(normalized_summary), str(normalized_page)],
                cwd=ROOT, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn('"utc_normalized_summary_accepted":true', result.stdout)


if __name__ == "__main__":
    unittest.main()
