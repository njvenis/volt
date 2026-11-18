from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RC3WorkflowContractTests(unittest.TestCase):
    def test_rc3_has_native_candidates_and_separate_reviewed_publisher(self):
        workflow = (ROOT / ".github/workflows/release-rc3.yml").read_text()
        self.assertIn("runner: ubuntu-24.04", workflow)
        self.assertIn("runner: ubuntu-24.04-arm", workflow)
        self.assertIn("test \"$(uname -m)\" = \"${{ matrix.machine }}\"", workflow)
        self.assertIn("docker build --platform \"${{ matrix.platform }}\"", workflow)
        self.assertIn("compose_release_qualification.py", workflow)
        self.assertIn("volt-rc3-candidate-${{ github.sha }}-linux-${{ matrix.arch }}", workflow)
        self.assertIn("environment: volt-rc1-publication", workflow)
        self.assertIn("inputs.publish_approved == true", workflow)
        self.assertIn("registry.py --version-tag 0.1.0-rc.3", workflow)
        self.assertIn("docker buildx imagetools create", workflow)
        self.assertIn("publication_verify.py", workflow)
        self.assertIn("archive.py verify", workflow)
        self.assertIn("archive.py load", workflow)
        self.assertIn("gh release create v0.1.0-rc.3 --target", workflow)
        self.assertNotIn("docker build --platform", workflow.split("  publish:", 1)[1])
        self.assertNotIn("packages: write", workflow.split("  native_candidate:", 1)[1].split("  retain_candidate:", 1)[0])

    def test_release_bootstrap_uses_trusted_source_before_load(self):
        instructions = (ROOT / "tools/release/VERIFY-RELEASE.md").read_text()
        self.assertLess(instructions.index("git clone --no-checkout"), instructions.index("archive.py verify"))
        self.assertLess(instructions.index("archive.py verify"), instructions.index("archive.py load"))
        self.assertIn("Do not execute or install any file from the archive", instructions)
        self.assertIn("release-rc3.yml@refs/heads/main", instructions)


if __name__ == "__main__":
    unittest.main()
