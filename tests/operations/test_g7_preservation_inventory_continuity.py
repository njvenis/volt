import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.g7_preservation_inventory import _assert_preserved_inventory
from uvm.operations.preservation import canonical_json


class PreservationInventoryContinuityTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.scope = ("local", "synthetic", "all")
        self.classes = [{"class_id": "product.source_evidence", "dto": {"state": "verified"},
            "members": [{"record_kind": "observation", "record_key": "observation:one",
                "record_sha256": "a" * 64, "expected_sha256": "b" * 64,
                "retained_at": "2026-01-01T00:00:00Z", "byte_bearing": True,
                "evidence_id": "00000000-0000-4000-8000-000000000001"}]}]
        payload = {"contract_id": "g7-data-preservation/v1", "purpose": "readcheck-report-v1",
            "deployment_id": "synthetic", "scope": list(self.scope),
            "storage_generation": "old-generation", "classes": copy.deepcopy(self.classes)}
        signature = self.key.sign(b"VOLT-G7-PRESERVATION\0readcheck-report-v1\0" + canonical_json(payload))
        self.document = {"payload": payload, "signature": {"algorithm": "Ed25519",
            "key_id": "fixture-key", "value": base64.b64encode(signature).decode("ascii")}}
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "previous.json"
        self.path.write_bytes(canonical_json(self.document))
        self.path.chmod(0o600)

    def tearDown(self):
        self.temp.cleanup()

    def _check(self, classes=None, generation="new-generation"):
        _assert_preserved_inventory(str(self.path), self.key, classes or self.classes,
            self.scope, "synthetic", generation, "fixture-key")

    def test_preserves_exact_member_preimage_across_generation(self):
        self._check()

    def test_rejects_changed_member_digest(self):
        changed = copy.deepcopy(self.classes)
        changed[0]["members"][0]["record_sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "continuity_mismatch"):
            self._check(changed)

    def test_rejects_missing_member(self):
        missing = copy.deepcopy(self.classes)
        missing[0]["members"] = []
        with self.assertRaisesRegex(ValueError, "continuity_mismatch"):
            self._check(missing)

    def test_rejects_replay_of_same_generation(self):
        with self.assertRaisesRegex(ValueError, "previous_report_binding_invalid"):
            self._check(generation="old-generation")


if __name__ == "__main__":
    unittest.main()
