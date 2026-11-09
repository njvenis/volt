from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools import build_compose_bundle


ROOT = Path(__file__).resolve().parents[2]


class ComposeBundleSourceTests(unittest.TestCase):
    def test_build_and_verify_accept_exact_selected_source_tree(self):
        with tempfile.TemporaryDirectory(prefix="volt-compose-source-") as temporary:
            output = Path(temporary) / "bundle.tar.gz"
            build_compose_bundle.build(output, "ghcr.io/njvenis/volt@sha256:" + "a" * 64,
                                       source_root=ROOT)
            build_compose_bundle.verify(output, source_root=ROOT)

    def test_verify_rejects_bundle_file_from_different_source_tree(self):
        with tempfile.TemporaryDirectory(prefix="volt-compose-source-mismatch-") as temporary:
            temp = Path(temporary)
            source = temp / "source"
            compose = source / "deploy" / "compose"
            compose.mkdir(parents=True)
            for name in build_compose_bundle.FILES:
                (compose / name).write_bytes((ROOT / "deploy" / "compose" / name).read_bytes())
            (compose / "README.md").write_text("contradictory source instructions\n")
            output = temp / "bundle.tar.gz"
            build_compose_bundle.build(output, "ghcr.io/njvenis/volt@sha256:" + "a" * 64,
                                       source_root=ROOT)
            with self.assertRaisesRegex(SystemExit, "selected VOLT source commit: README.md"):
                build_compose_bundle.verify(output, source_root=source)


if __name__ == "__main__":
    unittest.main()
