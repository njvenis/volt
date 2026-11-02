from __future__ import annotations

import copy
import unittest

from tools.g7_inventory_expectation import (
    _append_0061_byte_size_expectation,
    _append_0062_context_expectation,
    _migration_table_record,
)
from uvm.persistence.backup_settings_schema import g7_backup_projection_evidence
from uvm.persistence.ingestion_schema import collection_request_reservations
from tools.g7_product_inventory import digest, compare
from sqlalchemy import DateTime


class G7SchemaMigrationInventoryTests(unittest.TestCase):
    def test_0062_adds_empty_context_without_changing_legacy_rule_fields(self):
        payload = {"rule_id":"r", "rule_version":1,
            "workload_match_fields":["provisioning_key"],
            "verified_asset_locator":True, "definition_digest":"a"*64}
        table = {"columns":[{"name":name,"primary_key":name in {"rule_id","rule_version"}}
                    for name in payload],
            "constraints":{"checks":[]}, "rows":[{"key":["r",1],
                "payload":copy.deepcopy(payload), "payload_sha256":digest(payload)}], "row_count":1}
        expected = _append_0062_context_expectation(table)
        row = expected["rows"][0]["payload"]
        self.assertEqual({key:value for key,value in row.items()
            if key != "workload_context_fields"}, payload)
        self.assertEqual(row["workload_context_fields"], [])
        self.assertEqual(expected["rows"][0]["payload_sha256"], digest(row))
        self.assertIn({"name":"workload_context_fields", "type":"JSONB",
            "nullable":False, "primary_key":False, "default":"'[]'::jsonb"}, expected["columns"])

    def test_0059_projection_table_expectation_comes_from_migration_metadata(self):
        expected = _migration_table_record(g7_backup_projection_evidence)
        self.assertEqual([column["name"] for column in expected["columns"]], [
            "deployment_id", "application_evidence_record_id", "effective_evidence_record_id"])
        self.assertEqual(expected["constraints"]["primary_key"], ["deployment_id"])
        self.assertEqual(expected["rows"], [])

    def test_0060_reservation_table_expectation_pins_relational_constraints(self):
        expected = _migration_table_record(collection_request_reservations)
        self.assertEqual(expected["constraints"]["unique"], [["run_id", "attempt_no"]])
        self.assertEqual(expected["constraints"]["foreign_keys"], [{
            "constrained_columns": ["run_id", "run_revision"],
            "referred_schema": "public", "referred_table": "collection_runs",
            "referred_columns": ["run_id", "revision"], "options": {}, "comment": None}])
        self.assertEqual(expected["constraints"]["checks"], [
            "attempt_no > 0 AND page_ordinal > 0", "length(request_identity_sha256::text) = 64"])
        reserved_at = next(c for c in expected["columns"] if c["name"] == "reserved_at")
        self.assertEqual(reserved_at["type"], "TIMESTAMP WITH TIME ZONE")
        from uvm.persistence.ingestion_schema import collection_runs
        self.assertTrue(next(c for c in collection_runs.columns if c.name == "created_at").type.timezone)

    def test_0061_adds_null_size_without_changing_prior_evidence_fields(self):
        old_payload = {"evidence_id": "e-1", "sha256": "a" * 64,
            "evidence_ref": "private/ref", "registered_at": "2026-10-29T12:00:00+00:00"}
        evidence = {"columns": [{"name": name} for name in old_payload],
            "constraints": {"checks": ["schema_version = 1 AND length(sha256) = 64"]},
            "rows": [{"key": ["e-1"], "payload": copy.deepcopy(old_payload),
                "payload_sha256": digest(old_payload)}], "row_count": 1}
        evidence["columns"][0]["primary_key"] = True
        for column in evidence["columns"][1:]: column["primary_key"] = False
        baseline_evidence = copy.deepcopy(evidence)
        result = _append_0061_byte_size_expectation(evidence)
        self.assertEqual({k: v for k, v in result["rows"][0]["payload"].items()
            if k != "byte_size"}, old_payload)
        self.assertIsNone(result["rows"][0]["payload"]["byte_size"])
        self.assertEqual(result["rows"][0]["payload_sha256"],
            digest({**old_payload, "byte_size": None}))
        self.assertIn({"name": "byte_size", "type": "BIGINT", "nullable": True,
            "primary_key": False, "default": None}, result["columns"])
        self.assertIn("byte_size IS NULL OR byte_size >= 0 AND byte_size <= 16777216",
            result["constraints"]["checks"])
        baseline = {"uvm": {"ingestion_evidence": baseline_evidence}, "ce": {}, "media": []}
        candidate = copy.deepcopy(result)
        changed = candidate["rows"][0]["payload"]
        changed["evidence_ref"] = "private/changed"
        candidate["rows"][0]["payload_sha256"] = digest(changed)
        after = {"uvm": {"ingestion_evidence": candidate}, "ce": {}, "media": []}
        expected = {"uvm": {"ingestion_evidence": result}, "ce": {}, "media": []}
        self.assertEqual(compare(baseline, after, expected)["unexpected_inventory_change_count"], 1)

    def test_0061_rejects_mismatched_baseline_preimage(self):
        old_payload = {"evidence_id": "e-1", "evidence_ref": "private/ref"}
        evidence = {"columns": [{"name": "evidence_id", "primary_key": True},
                {"name": "evidence_ref", "primary_key": False}],
            "constraints": {"checks": []}, "row_count": 1,
            "rows": [{"key": ["e-1"], "payload": old_payload,
                "payload_sha256": digest({**old_payload, "evidence_ref": "private/old"})}]}
        with self.assertRaisesRegex(ValueError, "payload digest mismatch"):
            _append_0061_byte_size_expectation(evidence)

    def test_datetime_expectation_pins_timezone_attribute(self):
        from sqlalchemy import Column, MetaData, Table
        expected = _migration_table_record(Table("typed", MetaData(),
            Column("with_zone", DateTime(timezone=True)),
            Column("without_zone", DateTime(timezone=False))))
        self.assertEqual([c["type"] for c in expected["columns"]], [
            "TIMESTAMP WITH TIME ZONE", "TIMESTAMP WITHOUT TIME ZONE"])

    def test_inventory_comparator_rejects_timezone_schema_drift(self):
        from sqlalchemy import Column, MetaData, Table
        from tools.g7_inventory_expectation import _migration_table_record
        expected_table = _migration_table_record(Table("typed", MetaData(),
            Column("reserved_at", DateTime(timezone=True), nullable=False)))
        before = {"uvm": {"typed": copy.deepcopy(expected_table)}, "ce": {}, "media": []}
        after_table = copy.deepcopy(expected_table)
        after_table["columns"][0]["type"] = "TIMESTAMP WITHOUT TIME ZONE"
        after_table["schema_sha256"] = digest({"columns": after_table["columns"],
            "constraints": after_table["constraints"]})
        after = {"uvm": {"typed": after_table}, "ce": {}, "media": []}
        self.assertEqual(compare(before, after, before)["unexpected_inventory_change_count"], 1)


if __name__ == "__main__":
    unittest.main()
