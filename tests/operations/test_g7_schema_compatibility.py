from __future__ import annotations

import unittest
from pathlib import Path

from uvm.operations.schema_compatibility import validate_heads


class SchemaCompatibilityTests(unittest.TestCase):
    def test_current_runtime_requires_exact_0067_head_and_does_not_enable_upgrades(self):
        validate_heads(declared_head="0067", heads=["0067"], mode="normal")
        for mode, head in (("normal", "0066"), ("normal", "0068"),
                           ("upgrade-verification", "0066")):
            with self.subTest(mode=mode, head=head), self.assertRaises(ValueError):
                validate_heads(declared_head="0067", heads=[head], mode=mode,
                    compatibility_admitted=True)
        with self.assertRaises(ValueError):
            validate_heads(declared_head="0066", heads=["0066"], mode="normal")

    def test_only_empty_current_local_installation_may_resume_before_first_migration(self):
        validate_heads(declared_head="0067", heads=[], mode="normal", empty_local_installation=True)
        for head, heads, mode in (("0067", ["0066"], "normal"), ("0067", [], "upgrade-verification"),
                                  ("0062", [], "normal")):
            with self.subTest(head=head, heads=heads, mode=mode), self.assertRaises(ValueError):
                validate_heads(declared_head=head, heads=heads, mode=mode, empty_local_installation=True)

    def test_declared_head_matches_the_single_alembic_graph_head(self):
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        root = Path(__file__).resolve().parents[2]
        declared = (root / "docker/g7/schema-head").read_text(encoding="ascii").strip()
        graph_heads = ScriptDirectory.from_config(Config(str(root / "alembic.ini"))).get_heads()
        self.assertEqual(declared, "0067")
        self.assertEqual(graph_heads, [declared])

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
