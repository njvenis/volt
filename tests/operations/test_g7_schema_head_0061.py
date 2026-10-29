import unittest

from uvm.operations.schema_compatibility import validate_heads


class G7SchemaHead0061Tests(unittest.TestCase):
    def test_current_head_is_admitted_for_normal_start(self):
        validate_heads(declared_head="0061", heads=["0061"], mode="normal")

    def test_predecessor_heads_require_admitted_upgrade_mode(self):
        with self.assertRaisesRegex(ValueError, "incompatible"):
            validate_heads(declared_head="0061", heads=["0059"], mode="normal")
        for head in ("0058", "0059", "0060", "0061"):
            validate_heads(declared_head="0061", heads=[head], mode="upgrade-verification",
                compatibility_admitted=True)
        with self.assertRaisesRegex(ValueError, "incompatible"):
            validate_heads(declared_head="0061", heads=["0058"], mode="upgrade-verification")

    def test_multiple_or_unknown_heads_remain_rejected(self):
        for heads in ([], ["0058", "0061"], ["0062"]):
            with self.subTest(heads=heads), self.assertRaises(ValueError):
                validate_heads(declared_head="0061", heads=heads, mode="normal")


if __name__ == "__main__":
    unittest.main()
