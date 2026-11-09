from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from tools.release.verify_synthetic_artifact import EXPECTED_PAYLOAD, verify_artifact


def make_artifact(root: Path) -> None:
    payload = root / "payload/deep/synthetic.txt"
    payload.parent.mkdir(parents=True)
    payload.write_bytes(EXPECTED_PAYLOAD)
    digest = hashlib.sha256(EXPECTED_PAYLOAD).hexdigest()
    (root / "SHA256SUMS").write_text(f"{digest}  payload/deep/synthetic.txt\n", encoding="ascii")


class SyntheticArtifactTests(unittest.TestCase):
    def test_accepts_exact_nested_artifact_and_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "artifact"
            root.mkdir()
            make_artifact(root)
            verify_artifact(root)

    def test_rejects_checksum_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "artifact"
            root.mkdir()
            make_artifact(root)
            (root / "SHA256SUMS").write_text(f"{'0' * 64}  payload/deep/synthetic.txt\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                verify_artifact(root)

    def test_rejects_unexpected_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "artifact"
            root.mkdir()
            make_artifact(root)
            (root / "extra.txt").write_text("unexpected", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "file set"):
                verify_artifact(root)

    def test_rejects_symbolic_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "artifact"
            root.mkdir()
            make_artifact(root)
            (root / "payload/link.txt").symlink_to(root / "payload/deep/synthetic.txt")
            with self.assertRaisesRegex(ValueError, "symbolic links"):
                verify_artifact(root)
