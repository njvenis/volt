from __future__ import annotations

import copy
import unittest

from tools.g7_inventory_expectation import (
    _append_0061_byte_size_expectation,
    _migration_table_record,
)
from uvm.persistence.backup_settings_schema import g7_backup_projection_evidence
from uvm.persistence.ingestion_schema import collection_request_reservations
from tools.g7_product_inventory import digest


class G7SchemaMigrationInventoryTests(unittest.TestCase):
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

    def test_0061_adds_null_size_without_changing_prior_evidence_fields(self):
        old_payload = {"evidence_id": "e-1", "sha256": "a" * 64,
            "evidence_ref": "private/ref", "registered_at": "2026-10-29T12:00:00+00:00"}
        evidence = {"columns": [{"name": name} for name in old_payload],
            "constraints": {"checks": ["schema_version = 1 AND length(sha256) = 64"]},
            "rows": [{"key": ["e-1"], "payload": copy.deepcopy(old_payload),
                "payload_sha256": digest(old_payload)}]}
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


if __name__ == "__main__":
    unittest.main()
