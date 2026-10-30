import unittest

from uvm.operations.schema_compatibility import validate_heads


class G7SchemaHead0062Tests(unittest.TestCase):
    def test_normal_mode_requires_exact_0062(self):
        validate_heads(declared_head="0062", heads=["0062"], mode="normal")
        for heads in (["0061"], ["0062", "0061"], [], ["0058"]):
            with self.subTest(heads=heads), self.assertRaises(ValueError):
                validate_heads(declared_head="0062", heads=heads, mode="normal")

    def test_upgrade_verification_admits_only_single_ordered_path_heads(self):
        for head in ("0058", "0059", "0060", "0061", "0062"):
            validate_heads(declared_head="0062", heads=[head],
                mode="upgrade-verification", compatibility_admitted=True)
        for heads in ([], ["0058", "0062"], ["0063"]):
            with self.subTest(heads=heads), self.assertRaises(ValueError):
                validate_heads(declared_head="0062", heads=heads,
                    mode="upgrade-verification", compatibility_admitted=True)
        with self.assertRaises(ValueError):
            validate_heads(declared_head="0062", heads=["0061"],
                mode="upgrade-verification", compatibility_admitted=False)
