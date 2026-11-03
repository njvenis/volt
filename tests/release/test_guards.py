import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]


class ApprovalGuardTests(unittest.TestCase):
    def call(self, approved, data):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "environment.json"
            path.write_text(json.dumps(data))
            return subprocess.run([sys.executable, str(ROOT / "tools/release/guards.py"),
                                   "--approved", approved, "--environment-json", str(path),
                                   "--approval-reference", "run-17:maintainer"], capture_output=True, text=True)

    def test_absent_approval_is_rejected(self):
        result = self.call("false", {"protection_rules": [{"type": "required_reviewers", "reviewers": [{"id": 1}]}]})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("explicitly set", result.stderr)

    def test_unprotected_environment_is_rejected(self):
        result = self.call("true", {"protection_rules": []})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required human reviewer", result.stderr)

    def test_environment_with_reviewer_and_explicit_approval_passes(self):
        result = self.call("true", {"protection_rules": [{"type": "required_reviewers", "reviewers": [{"id": 1}]}]})
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
