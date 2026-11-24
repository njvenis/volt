from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools import build_compose_bundle


ROOT = Path(__file__).resolve().parents[2]
RUNTIME = "127.0.0.1:46150/volt@sha256:" + "a" * 64
VERIFIER = "127.0.0.1:46150/volt-installer-verifier@sha256:" + "b" * 64


class ComposeBundleSourceTests(unittest.TestCase):
    def test_build_and_verify_accept_exact_selected_source_tree(self):
        with tempfile.TemporaryDirectory(prefix="volt-compose-source-") as temporary:
            output = Path(temporary) / "bundle.tar.gz"
            build_compose_bundle.build(output, RUNTIME, source_root=ROOT,
                local_admission_fixture=True, verifier_reference=VERIFIER)
            build_compose_bundle.verify(output, source_root=ROOT, local_admission_fixture=True)

    def test_verify_rejects_bundle_file_from_different_source_tree(self):
        with tempfile.TemporaryDirectory(prefix="volt-compose-source-mismatch-") as temporary:
            temp = Path(temporary)
            source = temp / "source"
            compose = source / "deploy" / "compose"
            compose.mkdir(parents=True)
            for name in build_compose_bundle.RC4_FILES:
                source_name = "README.rc4.md" if name == "README.md" else name
                (compose / source_name).write_bytes((ROOT / "deploy" / "compose" / source_name).read_bytes())
            (compose / "README.rc4.md").write_text("contradictory source instructions\n")
            output = temp / "bundle.tar.gz"
            build_compose_bundle.build(output, RUNTIME, source_root=ROOT,
                local_admission_fixture=True, verifier_reference=VERIFIER)
            with self.assertRaisesRegex(SystemExit, "selected VOLT source commit: README.md"):
                build_compose_bundle.verify(output, source_root=source, local_admission_fixture=True)


if __name__ == "__main__":
    unittest.main()
