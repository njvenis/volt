from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class RC4ReleaseWorkflowTests(unittest.TestCase):
    def test_publication_snapshot_is_defined_inside_its_shell_step(self):
        workflow = (ROOT / ".github/workflows/release-rc4.yml").read_text()
        publish = workflow.split("      - name: Publish and verify the signed multi-platform assets", 1)[1]
        self.assertIn('expected_snapshot="sha256:$(git archive --format=tar "$CANDIDATE_SOURCE_SHA"', publish)
        self.assertIn('"$expected_snapshot"', publish)
        self.assertIn('source-snapshot.txt")" = "$expected_snapshot"', publish)

    def test_workflow_invokes_the_supported_package_builder_cli(self):
        workflow = (ROOT / ".github/workflows/release-rc4.yml").read_text()
        self.assertRegex(workflow, r"python3 tools/release/build_easy_installer\.py \\\s+--output")
        self.assertNotIn("tools/release/build_easy_installer.py build", workflow)

    def test_native_runtime_build_selects_platform_specific_pinned_ce_image(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn('CE_IMAGE="$(python3 tools/release/portable_demo.py ce-image --platform "linux/$ARCH")"', workflow)
        self.assertIn('--build-arg "CE_IMAGE=$CE_IMAGE"', workflow)


if __name__ == "__main__":
    unittest.main()
