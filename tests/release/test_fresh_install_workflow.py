from pathlib import Path
import json
import os
import shlex
import subprocess
import sys
import tempfile
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

    def test_installed_scanner_is_visible_in_the_same_workflow_step(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        step = workflow.split("- name: Fail-closed full-image vulnerability scan", 1)[1].split("\n      - name:", 1)[0]
        script = "\n".join(line[10:] for line in step.split("run: |\n", 1)[1].splitlines())
        version = next(line.split("=", 1)[1] for line in (ROOT / "tools/release/tools.lock").read_text().splitlines() if line.startswith("trivy_version="))
        image_id = "sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binaries = directory / "bin"
            binaries.mkdir()
            (binaries / "python3").symlink_to(sys.executable)
            (binaries / "cat").symlink_to("/bin/cat")
            tools = directory / "installed-tools"
            tools.mkdir()
            (directory / "image-id.txt").write_text(image_id)
            report = {"SchemaVersion": 2, "ArtifactType": "container_image", "Metadata": {"ImageID": image_id, "OS": {"Family": "debian", "Name": "13"}}, "Results": [{"Target": "fixture", "Class": "os-pkgs", "Type": "debian", "Vulnerabilities": []}]}
            scanner = "#!" + sys.executable + "\nimport json, sys\nfrom pathlib import Path\n"
            scanner += "if '--version' in sys.argv: print(" + repr("Version: " + version) + ")\n"
            scanner += "else: Path(sys.argv[sys.argv.index('--output') + 1]).write_text(" + repr(json.dumps(report)) + ")\n"
            installer = directory / "installer.py"
            installer.write_text("from pathlib import Path\np = Path(" + repr(str(tools / "trivy")) + ")\np.write_text(" + repr(scanner) + ")\np.chmod(0o700)\n")
            script = script.replace("python3 tools/release/install_trivy.py", "python3 " + shlex.quote(str(installer)))
            script = script.replace("/tmp/volt-release-tools", str(tools))
            environment = dict(os.environ, PATH=str(binaries), RELEASE_OUT=str(directory), GITHUB_PATH=str(directory / "github-path"))
            result = subprocess.run(["/bin/bash", "-e", "-c", script], cwd=ROOT, env=environment, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads((directory / "release-scan.json").read_text()), report)
            broken = script.replace('export PATH="' + str(tools) + ':$PATH"', 'echo ' + shlex.quote(str(tools)) + ' >> "$GITHUB_PATH"')
            result = subprocess.run(["/bin/bash", "-e", "-c", broken], cwd=ROOT, env=environment, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("pinned Trivy binary is required", result.stderr)

    def test_release_scope_is_explicitly_fresh_install_only(self):
        for name in ("docs/releasing.md", "docs/deployment.md", "tools/release/launcher-guide.txt"):
            with self.subTest(document=name):
                document = (ROOT / name).read_text().lower()
                self.assertIn("fresh", document)
                self.assertIn("historical", document)


if __name__ == "__main__":
    unittest.main()
