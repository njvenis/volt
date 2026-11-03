import json
import re
import tomllib
import unittest
from pathlib import Path


class GitleaksPolicyTests(unittest.TestCase):
    def test_exceptions_target_the_rule_instead_of_skipping_whole_files(self):
        root = Path(__file__).resolve().parents[2]
        policy = tomllib.loads((root / "tools/release/gitleaks.toml").read_text())
        for exception in policy["allowlists"]:
            with self.subTest(description=exception["description"]):
                self.assertEqual(exception["targetRules"], ["generic-api-key"])
                self.assertNotIn("ruleIDs", exception)
                self.assertEqual(exception["condition"], "AND")
                self.assertTrue(exception["regexes"])

    def test_public_key_checksum_exception_requires_exact_path_and_value(self):
        root = Path(__file__).resolve().parents[2]
        policy = tomllib.loads((root / "tools/release/gitleaks.toml").read_text())
        exception = next(row for row in policy["allowlists"] if "PostgreSQL" in row["description"])
        path = "tools/notices/debian-source-catalog.json"
        catalog = json.loads((root / path).read_text())
        checksum = catalog["trust_inputs"]["postgresql_pgdg"]["key_sha256"]
        line = f'  "key_sha256": "{checksum}",'
        self.assertEqual(exception["regexTarget"], "line")
        self.assertTrue(any(re.search(pattern, path) for pattern in exception["paths"]))
        self.assertFalse(any(re.search(pattern, "other.json") for pattern in exception["paths"]))
        self.assertTrue(any(re.search(pattern, line) for pattern in exception["regexes"]))
        changed = ("9" if checksum[0] != "9" else "0") + checksum[1:]
        self.assertFalse(any(re.search(pattern, line.replace(checksum, changed)) for pattern in exception["regexes"]))
