from pathlib import Path
import io
import json
import os
import subprocess
import tarfile
import tempfile
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

    def test_release_bootstrap_resolves_fixed_tag_before_helper_and_archive_verification(self):
        instructions = (ROOT / "tools/release/VERIFY-RELEASE.md").read_text()
        block = instructions.split("```sh\n", 1)[1].split("\n```", 1)[0]
        self.assertLess(block.index("git ls-remote"), block.index("git clone"))
        self.assertLess(block.index("git clone"), block.index("install_cosign.py"))
        self.assertLess(instructions.index("archive.py verify"), instructions.index("archive.py load"))
        self.assertIn('--source-sha "$SOURCE_SHA"', instructions)
        self.assertIn("Do not read its manifest to choose source code, a verifier, or an installer", instructions)
        self.assertIn("release-rc3.yml@refs/heads/main", instructions)
        source_assignment = next(line for line in block.splitlines() if line.startswith("SOURCE_SHA="))
        self.assertIn("TAG_REFS", source_assignment)
        self.assertNotIn("ARCHIVE", source_assignment)
        self.assertNotIn("manifest.json", block[:block.index("git clone")])

    def test_malicious_archive_manifest_cannot_select_bootstrap_source(self):
        instructions = (ROOT / "tools/release/VERIFY-RELEASE.md").read_text()
        block = instructions.split("```sh\n", 1)[1].split("\n```", 1)[0]
        start = block.index("TAG_REFS=")
        end = block.index("git clone", start)
        pin_source = block[start:end] + "\nprintf '%s\\n' \"$SOURCE_SHA\"\n"
        trusted_source = "a" * 40
        malicious_source = "e" * 40
        with tempfile.TemporaryDirectory(prefix="volt-rc3-bootstrap-negative-") as temporary:
            root = Path(temporary)
            archive = root / "attacker.tar.gz"
            manifest = json.dumps({"source_commit": malicious_source}).encode()
            with tarfile.open(archive, "w:gz") as bundle:
                item = tarfile.TarInfo("manifest.json")
                item.size = len(manifest)
                bundle.addfile(item, io.BytesIO(manifest))
            # Model ls-remote as a shell function: keep fixture data in process
            # memory instead of interpolating it into a persisted executable.
            fake_git = """git() {
  if [ "$1" = ls-remote ]; then
    printf '%s\\t%s\\n' "$VOLT_TEST_TRUSTED_SOURCE" 'refs/tags/v0.1.0-rc.3'
  else
    return 91
  fi
}
"""
            environment = {
                "PATH": os.defpath,
                "VOLT_TEST_TRUSTED_SOURCE": trusted_source,
                "ARCHIVE": str(archive),
                "REPOSITORY": "https://github.com/njvenis/volt.git",
                "RELEASE_TAG": "v0.1.0-rc.3",
            }
            result = subprocess.run(["bash", "-c", fake_git + pin_source], env=environment,
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), trusted_source)
            self.assertNotEqual(result.stdout.strip(), malicious_source)
            self.assertEqual({path.name for path in root.iterdir()}, {"attacker.tar.gz"})


if __name__ == "__main__":
    unittest.main()
