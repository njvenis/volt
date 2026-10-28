from __future__ import annotations

import unittest

from uvm.operations.schema_compatibility import validate_heads


class SchemaCompatibilityTests(unittest.TestCase):
    def test_image_accepts_only_its_declared_normal_head(self):
        validate_heads(declared_head="0058", heads=["0058"], mode="normal")
        validate_heads(declared_head="0059", heads=["0059"], mode="normal")
        for heads in ([], ["0057"], ["0058", "0059"]):
            with self.subTest(heads=heads), self.assertRaises(ValueError):
                validate_heads(declared_head="0059", heads=heads, mode="normal")

    def test_empty_initialization_is_separate_from_existing_cluster_admission(self):
        validate_heads(declared_head="0059", heads=[], mode="normal", empty_cluster=True)
        with self.assertRaises(ValueError):
            validate_heads(declared_head="0059", heads=[], mode="normal")
        with self.assertRaises(ValueError):
            validate_heads(declared_head="0059", heads=[], mode="upgrade-verification",
                empty_cluster=True)

    def test_only_explicitly_admitted_0058_to_0059_verification_is_allowed(self):
        validate_heads(declared_head="0059", heads=["0058"], mode="upgrade-verification",
            compatibility_admitted=True)
        validate_heads(declared_head="0059", heads=["0059"], mode="upgrade-verification",
            compatibility_admitted=True)
        for mode, admitted in (("normal", True), ("upgrade-verification", False)):
            with self.subTest(mode=mode, admitted=admitted), self.assertRaises(ValueError):
                validate_heads(declared_head="0059", heads=["0058"], mode=mode,
                    compatibility_admitted=admitted)
        with self.assertRaises(ValueError):
            validate_heads(declared_head="0058", heads=["0059"], mode="normal")


if __name__ == "__main__":
    unittest.main()
