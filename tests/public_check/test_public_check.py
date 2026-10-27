"""Regression tests for tracked-file hygiene scanning."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
CHECKER = REPO / "tools" / "public_check.py"


class TrackedFileScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        (self.root / "README.md").write_text("# Synthetic tree\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.root), "add", "README.md"], check=True
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def scan(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER), str(self.root)],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_untracked_python_cache_is_not_exported_or_scanned(self) -> None:
        cache = self.root / "tests" / "__pycache__" / "generated.pyc"
        cache.parent.mkdir(parents=True)
        cache.write_bytes(b"\x00\xffgenerated cache")

        result = self.scan()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("scanned 1 UTF-8 files", result.stdout)

    def test_tracked_extensionless_binary_is_rejected(self) -> None:
        artifact = self.root / "data" / "payload"
        artifact.parent.mkdir()
        artifact.write_bytes(b"\x00\xfftracked binary")
        subprocess.run(
            ["git", "-C", str(self.root), "add", "data/payload"], check=True
        )

        result = self.scan()

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("data/payload", result.stdout)
        self.assertIn("non-UTF-8/binary file is not approved", result.stdout)


if __name__ == "__main__":
    unittest.main()
