from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class FreshInstallWorkflowTests(unittest.TestCase):
    def test_rc1_release_gates_the_saved_image_through_fresh_no_build_preview(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertEqual(workflow.count("docker build --platform linux/amd64"), 1)
        self.assertIn('docker save --output "$out/image.tar" volt-rc1:candidate', workflow)
        self.assertIn('org.opencontainers.image.source="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY"', workflow)
        self.assertIn('docker load --input "$out/image.tar"', workflow)
        self.assertIn("tools/notices/prepare_release_sources.py --output", workflow)
        self.assertIn("--debian-dispositions", workflow)
        self.assertIn("debian-source-dispositions.json", workflow)
        self.assertIn("--debian-developer-keyring", workflow)
        self.assertIn("start rc1 --no-build", workflow)
        self.assertIn("--expected-image-id \"$image_id\"", workflow)
        self.assertIn("--expected-image-source-revision \"$GITHUB_SHA\"", workflow)
        self.assertIn("smoke rc1 --readback", workflow)
        self.assertIn("destroy rc1", workflow)

    def test_release_scope_is_explicitly_fresh_install_only(self):
        for name in ("docs/releasing.md", "docs/deployment.md", "tools/release/launcher-guide.txt"):
            with self.subTest(document=name):
                document = (ROOT / name).read_text().lower()
                self.assertIn("fresh", document)
                self.assertIn("historical", document)


if __name__ == "__main__":
    unittest.main()
