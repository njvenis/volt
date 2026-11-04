from pathlib import Path
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class FreshInstallWorkflowTests(unittest.TestCase):
    def test_candidate_and_publish_are_separate_and_publish_reuses_named_run(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("candidate_run_id == ''", workflow)
        self.assertIn("inputs.candidate_run_id != '' && inputs.publish_approved == true", workflow)
        self.assertIn("verify_candidate_run.py", workflow)
        self.assertIn("verify_candidate_artifact.py", workflow)
        self.assertIn("run-id: ${{ inputs.candidate_run_id }}", workflow)
        self.assertIn('--run-id "$CANDIDATE_RUN_ID"', workflow)
        self.assertIn('printf \'%s\\n\' "$GITHUB_RUN_ID" > "$out/prepare-run-id.txt"', workflow)
        self.assertIn('"voltCandidatePreparationRun": os.environ["VOLT_PREPARE_RUN_ID"]', workflow)
        self.assertIn('"voltPublicationRun": os.environ["GITHUB_RUN_ID"]', workflow)
        publish = workflow.split("  publish:",1)[1]
        self.assertIn("environment: volt-rc1-publication", publish)
        self.assertIn("packages: write", publish)
        self.assertIn("id-token: write", publish)
        self.assertNotIn("docker build", publish)
        self.assertIn("volt-rc2-compose-qualification", workflow)
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("uv run python -m unittest discover -s tests/release -v", ci)
    def test_rc2_release_gates_the_saved_image_through_fresh_no_build_preview(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertEqual(workflow.count("docker build --platform linux/amd64"), 1)
        self.assertIn('docker save --output "$out/image.tar" volt-rc2:candidate', workflow)
        self.assertIn('org.opencontainers.image.source="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY"', workflow)
        self.assertIn('docker load --input "$out/image.tar"', workflow)
        self.assertIn("tools/notices/prepare_release_sources.py --output", workflow)
        self.assertIn("--debian-dispositions", workflow)
        self.assertIn("debian-source-dispositions.json", workflow)
        self.assertIn("--debian-developer-keyring", workflow)
        self.assertIn("start rc2 --no-build", workflow)
        self.assertIn("--expected-image-id \"$image_id\"", workflow)
        self.assertIn("--expected-image-source-revision \"$GITHUB_SHA\"", workflow)
        self.assertIn("smoke rc2 --readback", workflow)
        self.assertIn("destroy rc2", workflow)

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

    def test_candidate_transfer_preserves_debian_epoch_paths_and_exact_files(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()

        def script(name):
            step = workflow.split("- name: " + name, 1)[1].split("\n      - name:", 1)[0]
            return "\n".join(line[10:] for line in step.split("run: |\n", 1)[1].splitlines())

        upload = workflow.split("- name: Upload exact candidate inputs; no publication credentials", 1)[1].split("\n  publish:", 1)[0]
        self.assertIn("path: ${{ runner.temp }}/volt-rc2-candidate.tar", upload)
        self.assertIn("path: ${{ runner.temp }}/volt-rc2-transfer", workflow)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "candidate"
            source.mkdir()
            files = {"image.tar": b"immutable-image-bytes", "image-id.txt": b"sha256:fixture", "notices/notices/debian-source-material/attr-1:2.5.2-3/attr_2.5.2-3.dsc": b"signed-source-fixture", "notices/.retained": b"hidden-control", "release-scan.json": b"complete-scan-fixture"}
            for name, data in files.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            original = source / "notices/notices/debian-source-material/attr-1:2.5.2-3/attr_2.5.2-3.dsc"
            linked_name = "source-preparation/debian-source-material/attr_2.5.2-3.dsc"
            linked = source / linked_name
            linked.parent.mkdir(parents=True)
            os.link(original, linked)
            self.assertEqual(original.stat().st_ino, linked.stat().st_ino)
            files[linked_name] = original.read_bytes()
            environment = dict(os.environ, RELEASE_OUT=str(source), RUNNER_TEMP=str(directory))
            packed = subprocess.run(["/bin/bash", "-e", "-c", script("Pack exact candidate inputs for portable artifact transfer")], cwd=ROOT, env=environment, text=True, capture_output=True)
            self.assertEqual(packed.returncode, 0, packed.stdout + packed.stderr)
            with tarfile.open(directory / "volt-rc2-candidate.tar") as archive:
                self.assertTrue(all(member.isfile() or member.isdir() for member in archive))
            shutil.rmtree(source)
            transfer = directory / "volt-rc2-transfer"
            transfer.mkdir()
            (directory / "volt-rc2-candidate.tar").rename(transfer / "volt-rc2-candidate.tar")
            restored = subprocess.run(["/bin/bash", "-e", "-c", script("Restore exact candidate inputs")], cwd=ROOT, env=environment, text=True, capture_output=True)
            self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)
            output = directory / "volt-rc2"
            observed = {path.relative_to(output).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in output.rglob("*") if path.is_file()}
            self.assertEqual(observed, {name: hashlib.sha256(data).hexdigest() for name, data in files.items()})

    def test_release_scope_is_explicitly_fresh_install_only(self):
        for name in ("docs/releasing.md", "docs/deployment.md", "tools/release/launcher-guide.txt"):
            with self.subTest(document=name):
                document = (ROOT / name).read_text().lower()
                self.assertIn("fresh", document)
                self.assertIn("historical", document)


if __name__ == "__main__":
    unittest.main()
