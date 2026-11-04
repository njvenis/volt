import json
import hashlib
import os
import subprocess
import sys
import tarfile
import gzip
import io
import shutil
import base64
import contextlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import ANY, patch

sys.path.insert(0, str(Path(__file__).parents[2] / "tools" / "release"))
import archive

class OfflineArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = Path(tempfile.mkdtemp(prefix="volt-test-signing-key-"))
        cls.key = cls.keys / "test"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(cls.key)], check=True,
                       capture_output=True, text=True)
        cls.public = cls.keys / "test.pub"
        subprocess.run(["openssl", "pkey", "-in", str(cls.key), "-pubout", "-out", str(cls.public)], check=True,
                       capture_output=True, text=True)
        cls.other = cls.keys / "other"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(cls.other)], check=True,
                       capture_output=True, text=True)
        cls.other_public = cls.keys / "other.pub"
        subprocess.run(["openssl", "pkey", "-in", str(cls.other), "-pubout", "-out", str(cls.other_public)], check=True,
                       capture_output=True, text=True)

    def build_signed(self, root):
        package = root / "bundle"
        package.mkdir()
        (package / "notices").mkdir()
        repo = root / "source-repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
        (repo / "README.md").write_text("fixture source\n")
        (repo / "tools").mkdir()
        helper_bytes = b"# exact maintained helper fixture\n"
        (repo / "tools" / "g7_local_preview.py").write_bytes(helper_bytes)
        subprocess.run(["git", "-C", str(repo), "add", "README.md", "tools/g7_local_preview.py"], check=True)
        env = {**os.environ, "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
               "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        subprocess.run(["git", "-C", str(repo), "commit", "-m", "fixture"], check=True, env=env, capture_output=True)
        source_sha = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        # Match actions/checkout at an exact SHA: the worktree is detached and has no local main.
        detached = root / "detached-source"
        subprocess.run(["git", "clone", "--quiet", "--no-checkout", str(repo), str(detached)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(detached), "checkout", "--quiet", "--detach", source_sha], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(detached), "update-ref", "-d", "refs/heads/main"], check=True, capture_output=True)
        self.assertFalse(subprocess.check_output(["git", "-C", str(detached), "for-each-ref", "--format=%(refname:short)", "refs/heads"], text=True).strip())
        subprocess.run(["git", "-C", str(detached), "bundle", "create", str(package / "source.bundle"), "HEAD"], check=True, capture_output=True)
        recipient = root / "recipient"
        subprocess.run(["git", "clone", "--quiet", "--no-checkout", str(package / "source.bundle"), str(recipient)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(recipient), "checkout", "--quiet", "--detach", source_sha], check=True, capture_output=True)
        self.assertEqual(subprocess.check_output(["git", "-C", str(recipient), "rev-parse", "HEAD"], text=True).strip(), source_sha)
        subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", "--output", str(package / "source.tar"), "HEAD"], check=True)
        layer = b"fixture layer bytes"
        diff = "sha256:" + hashlib.sha256(layer).hexdigest()
        config = {"os": "linux", "architecture": "amd64", "config": {"Labels": {
            "org.opencontainers.image.revision": source_sha, "org.opencontainers.image.version": "0.1.0-rc.1"}},
            "rootfs": {"type": "layers", "diff_ids": [diff]}}
        config_bytes = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
        image_id = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
        with tarfile.open(package / "image.tar", "w") as image:
            import io
            entries = [(image_id.split(":", 1)[1] + ".json", config_bytes), ("layer.tar", layer),
                       ("manifest.json", json.dumps([{"Config": image_id.split(":", 1)[1] + ".json", "RepoTags": ["volt:fixture"], "Layers": ["layer.tar"]}]).encode())]
            for name, data in entries:
                info = tarfile.TarInfo(name); info.size = len(data); image.addfile(info, io.BytesIO(data))
        for name, contents in {
            "tools-g7-local-preview.py": helper_bytes,
            "launcher-guide.txt": b"start fixture\n",
            "sbom.syft.json": b'{"artifacts": []}\n',
            "sbom.spdx.json": b'{"packages": []}\n',
            "release-scan.json": json.dumps({"SchemaVersion":2,"ArtifactType":"container_image","Metadata":{"ImageID":image_id},"Results":[{"Target":"fixture","Class":"os-pkgs","Type":"debian"}]}).encode()+b"\n",
            "notices/example.txt": b"fixture notice\n",
            "notices/manifest.json": b"nested signed manifest name\n",
            "notices/SHA256SUMS": b"nested signed checksum name\n",
            "VERIFY.txt": b"test-only verification instructions\n",
            "provenance.json": json.dumps({"buildDefinition":{"buildType":"https://github.com/Attestations/GitHubActionsWorkflow@v1","externalParameters":{"workflow":{"ref":"njvenis/volt/.github/workflows/release.yml@refs/heads/main","repository":"https://github.com/njvenis/volt"},"source":{"uri":"https://github.com/njvenis/volt","ref":source_sha}},"internalParameters":{},"resolvedDependencies":[{"uri":"git+https://github.com/njvenis/volt","digest":{"gitCommit":source_sha}}]},"runDetails":{"builder":{"id":"https://github.com/actions/runner"},"metadata":{"invocationId":"https://github.com/njvenis/volt/actions/runs/123"}}}).encode()+b"\n",
            "registry-digest.txt": b"sha256:" + b"c" * 64 + b"\n",
            "notice-manifest.json": json.dumps({"schema":"volt-notice-inventory/v1", "image_id":image_id, "platform":"linux/amd64"}).encode()+b"\n",
        }.items():
            (package / name).write_bytes(contents)
        self.source_sha, self.image_id = source_sha, image_id
        manifest = archive.build_manifest(package, "0.1.0-rc.1", source_sha, image_id,
                                          "linux/amd64", archive.EXPECTED_IDENTITY, archive.EXPECTED_ISSUER,
                                          "sha256:" + "c" * 64)
        (package / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        with patch.object(sys, "argv", ["archive.py", "sign", "--directory", str(package), "--key", str(self.key)]):
            self.assertEqual(archive.main(), 0)
        result = root / "volt-rc1.tar"
        with patch.object(sys, "argv", ["archive.py", "pack", "--directory", str(package),
                                                        "--archive", str(result), "--test-public-key", str(self.public)]):
            self.assertEqual(archive.main(), 0)
        return package, result

    def build_rc2_signed(self, root):
        package = root / "rc2-bundle"
        (package / "notices").mkdir(parents=True)
        repo = root / "rc2-source"
        repo.mkdir()
        subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
        compose_source = Path(__file__).parents[2] / "deploy" / "compose"
        (repo / "deploy" / "compose").mkdir(parents=True)
        for name in archive.COMPOSE_BUNDLE_FILES:
            shutil.copy2(compose_source / name, repo / "deploy" / "compose" / name)
        (repo / "tools").mkdir()
        shutil.copy2(Path(__file__).parents[2] / "tools" / "build_compose_bundle.py", repo / "tools" / "build_compose_bundle.py")
        env = {**os.environ, "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
               "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-m", "RC2 compose source"], check=True, env=env, capture_output=True)
        source_sha = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        subprocess.run(["git", "-C", str(repo), "bundle", "create", str(package / "source.bundle"), "HEAD"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", "--output", str(package / "source.tar"), "HEAD"], check=True)
        source_snapshot = "sha256:" + archive.sha(package / "source.tar")
        registry_digest = "sha256:" + "c" * 64
        bundle = package / "volt-compose.tar.gz"
        subprocess.run([sys.executable, str(repo / "tools" / "build_compose_bundle.py"), "build",
                        "--output", str(bundle), "--image-reference", f"ghcr.io/njvenis/volt@{registry_digest}"],
                       cwd=repo, check=True, capture_output=True, text=True)
        layer = b"fixture RC2 layer bytes"
        diff = "sha256:" + hashlib.sha256(layer).hexdigest()
        config = {"os": "linux", "architecture": "amd64", "config": {"Labels": {
            "org.opencontainers.image.revision": source_sha, "org.opencontainers.image.version": archive.EXPECTED_VERSION,
            "org.volt.oidc-deployment-modes": "demo,external", "org.volt.compose-install.contract": "1",
            "org.volt.compose.source-snapshot": source_snapshot}}, "rootfs": {"type": "layers", "diff_ids": [diff]}}
        config_bytes = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
        image_id = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
        with tarfile.open(package / "image.tar", "w") as image:
            import io
            entries = [(image_id.split(":", 1)[1] + ".json", config_bytes), ("layer.tar", layer),
                       ("manifest.json", json.dumps([{"Config": image_id.split(":", 1)[1] + ".json", "RepoTags": ["volt:rc2-fixture"], "Layers": ["layer.tar"]}]).encode())]
            for name, data in entries:
                info = tarfile.TarInfo(name); info.size = len(data); image.addfile(info, io.BytesIO(data))
        payload = {
            "sbom.syft.json": b'{"artifacts": []}\n', "sbom.spdx.json": b'{"packages": []}\n',
            "release-scan.json": json.dumps({"SchemaVersion": 2, "ArtifactType": "container_image", "Metadata": {"ImageID": image_id}, "Results": [{"Target": "fixture", "Class": "os-pkgs", "Type": "debian"}]}).encode()+b"\n",
            "notices/example.txt": b"fixture RC2 notice\n", "notice-manifest.json": json.dumps({"schema": "volt-notice-inventory/v1", "image_id": image_id, "platform": "linux/amd64"}).encode()+b"\n",
            "VERIFY.txt": b"test-only RC2 verification instructions\n",
            "provenance.json": json.dumps({"buildDefinition": {"buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1", "externalParameters": {"workflow": {"ref": "njvenis/volt/.github/workflows/release.yml@refs/heads/main", "repository": "https://github.com/njvenis/volt"}, "source": {"uri": "https://github.com/njvenis/volt", "ref": source_sha}}, "internalParameters": {}, "resolvedDependencies": [{"uri": "git+https://github.com/njvenis/volt", "digest": {"gitCommit": source_sha}}]}, "runDetails": {"builder": {"id": "https://github.com/actions/runner"}, "metadata": {"invocationId": "https://github.com/njvenis/volt/actions/runs/123"}}}).encode()+b"\n",
            "registry-digest.txt": (registry_digest+"\n").encode(),
        }
        for name, contents in payload.items():
            (package / name).write_bytes(contents)
        self.source_sha, self.image_id = source_sha, image_id
        for command in (
            ["archive.py", "prepare", "--directory", str(package), "--version", archive.EXPECTED_VERSION,
             "--source-sha", source_sha, "--image-id", image_id, "--registry-digest", registry_digest, "--platform", "linux/amd64"],
            ["archive.py", "sign", "--directory", str(package), "--key", str(self.key)],
        ):
            with patch.object(sys, "argv", command):
                self.assertEqual(archive.main(), 0)
        result = root / "volt-rc2.tar"
        with patch.object(sys, "argv", ["archive.py", "pack", "--directory", str(package), "--archive", str(result), "--test-public-key", str(self.public)]):
            self.assertEqual(archive.main(), 0)
        return package, result

    def test_release_workflow_bundle_command_works_in_exact_detached_checkout(self):
        workflow = (Path(__file__).parents[2] / ".github/workflows/release.yml").read_text()
        self.assertIn('git bundle create "$out/source.bundle" HEAD', workflow)
        self.assertNotIn('git bundle create "$out/source.bundle" "$GITHUB_SHA"', workflow)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package, _ = self.build_signed(root)
            detached = root / "detached-source"
            bundle = package / "source.bundle"
            bundle.unlink()
            # This is the exact command from the workflow, run after its HEAD == GITHUB_SHA guard.
            subprocess.run(["git", "-C", str(detached), "bundle", "create", str(bundle), "HEAD"],
                           check=True, capture_output=True, text=True)
            recipient = root / "workflow-recipient"
            subprocess.run(["git", "clone", "--quiet", "--no-checkout", str(bundle), str(recipient)],
                           check=True, capture_output=True, text=True)
            commit = subprocess.check_output(["git", "-C", str(detached), "rev-parse", "HEAD"], text=True).strip()
            subprocess.run(["git", "-C", str(recipient), "checkout", "--quiet", "--detach", commit],
                           check=True, capture_output=True, text=True)
            self.assertEqual(subprocess.check_output(["git", "-C", str(recipient), "rev-parse", "HEAD"], text=True).strip(), commit)

    def test_valid_signed_archive_verifies_offline_with_fixture_key(self):
        with tempfile.TemporaryDirectory() as temp:
            _, packed = self.build_signed(Path(temp))
            with patch.object(sys, "argv", ["archive.py", "verify", "--archive", str(packed),
                                                            "--test-public-key", str(self.public),
                                                            "--source-sha", self.source_sha,
                                                            "--image-id", self.image_id]):
                self.assertEqual(archive.main(), 0)

    def test_rc2_signed_archive_prepare_pack_verify_binds_digest_bundle_to_source(self):
        with tempfile.TemporaryDirectory() as temp:
            package, packed = self.build_rc2_signed(Path(temp))
            self.assertFalse((package / "tools-g7-local-preview.py").exists())
            with patch.object(sys, "argv", ["archive.py", "verify", "--archive", str(packed),
                                            "--test-public-key", str(self.public),
                                            "--source-sha", self.source_sha, "--image-id", self.image_id]), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(archive.main(), 0)

    def test_rc2_offline_instructions_select_local_image_id(self):
        verify = (Path(__file__).parents[2] / "tools" / "release" / "VERIFY.txt").read_text()
        readme = (Path(__file__).parents[2] / "deploy" / "compose" / "README.md").read_text()
        self.assertIn('["registry_digest"]', verify)
        self.assertIn('["image_id"]', verify)
        self.assertIn('--image "$image_id"', verify)
        self.assertIn("docker pull VOLT_RELEASE_IMAGE_REFERENCE", readme)
        self.assertIn("signed `manifest.json` `image_id` field", readme)
        with tempfile.TemporaryDirectory() as temp:
            package, _ = self.build_rc2_signed(Path(temp))
            manifest = json.loads((package / "manifest.json").read_text())
            self.assertRegex(manifest["image_id"], r"^sha256:[0-9a-f]{64}$")
            self.assertRegex(manifest["registry_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertNotEqual(manifest["image_id"], manifest["registry_digest"])

    def test_rc2_archive_requires_bundle_and_checksum(self):
        with tempfile.TemporaryDirectory() as temp:
            package, _ = self.build_rc2_signed(Path(temp))
            bundle = (package / "volt-compose.tar.gz").read_bytes()
            (package / "volt-compose.tar.gz").unlink()
            with self.assertRaisesRegex(ValueError, "required offline release file missing: volt-compose.tar.gz"):
                archive.build_manifest(package, archive.EXPECTED_VERSION, self.source_sha, self.image_id,
                    "linux/amd64", archive.EXPECTED_IDENTITY, archive.EXPECTED_ISSUER,
                    "sha256:" + "c" * 64)
            (package / "volt-compose.tar.gz").write_bytes(bundle)
            (package / "volt-compose.tar.gz.sha256").unlink()
            with self.assertRaisesRegex(ValueError, "required offline release file missing: volt-compose.tar.gz.sha256"):
                archive.build_manifest(package, archive.EXPECTED_VERSION, self.source_sha, self.image_id,
                    "linux/amd64", archive.EXPECTED_IDENTITY, archive.EXPECTED_ISSUER,
                    "sha256:" + "c" * 64)

    def test_rc2_archive_rejects_digest_consistent_bundle_source_contradiction(self):
        with tempfile.TemporaryDirectory() as temp:
            package, _ = self.build_rc2_signed(Path(temp))
            bundle = package / "volt-compose.tar.gz"
            with tarfile.open(bundle, "r:gz") as original:
                entries = {member.name: original.extractfile(member).read() for member in original.getmembers()}
            setup_name = f"volt-compose-{archive.EXPECTED_VERSION}/setup.py"
            entries[setup_name] += b"\n# fixture contradiction\n"
            manifest_name = f"volt-compose-{archive.EXPECTED_VERSION}/manifest.json"
            bundle_manifest = json.loads(entries[manifest_name])
            bundle_manifest["files"]["setup.py"] = hashlib.sha256(entries[setup_name]).hexdigest()
            entries[manifest_name] = (json.dumps(bundle_manifest, sort_keys=True, indent=2) + "\n").encode()
            with tarfile.open(bundle, "w:gz", format=tarfile.PAX_FORMAT) as rewritten:
                for name, contents in sorted(entries.items()):
                    member = tarfile.TarInfo(name); member.size = len(contents); rewritten.addfile(member, __import__("io").BytesIO(contents))
            (package / "volt-compose.tar.gz.sha256").write_text(f"{archive.sha(bundle)}  {bundle.name}\n")
            manifest = archive.build_manifest(package, archive.EXPECTED_VERSION, self.source_sha, self.image_id,
                "linux/amd64", archive.EXPECTED_IDENTITY, archive.EXPECTED_ISSUER, "sha256:" + "c" * 64)
            (package / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
            with patch.object(sys, "argv", ["archive.py", "sign", "--directory", str(package), "--key", str(self.key)]):
                self.assertEqual(archive.main(), 0)
            with self.assertRaisesRegex(ValueError, "Compose bundle source file differs from signed source.*setup.py"):
                archive.verify_directory(package, "cosign", public_key=self.public)

    def test_wrong_signer_identity_and_wrong_key_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            _, packed = self.build_signed(Path(temp))
            extracted = Path(temp) / "extracted"
            extracted.mkdir()
            archive.safe_extract(packed, extracted)
            with self.assertRaisesRegex(ValueError, "unexpected release signer"):
                archive.verify_directory(extracted, "cosign", public_key=self.public, identity="https://wrong.example/workflow")
            with self.assertRaisesRegex(ValueError, "public key identity mismatch"):
                archive.verify_directory(extracted, "cosign", public_key=self.other_public)

    def test_production_signing_requires_approval_reference(self):
        with tempfile.TemporaryDirectory() as temp:
            package, _ = self.build_signed(Path(temp))
            with patch.object(sys, "argv", ["archive.py", "sign", "--directory", str(package),
                                              "--production-oidc"]):
                self.assertEqual(archive.main(), 2)

    def test_payload_tampering_and_wrong_metadata_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            package, packed = self.build_signed(Path(temp))
            with self.assertRaisesRegex(ValueError, "source revision"):
                archive.verify_directory(package, "cosign", public_key=self.public, expected_source="c" * 40)
            (package / "image.tar").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "payload missing or digest mismatch"):
                archive.verify_directory(package, "cosign", public_key=self.public)

    def test_load_rejects_archive_config_mismatch_before_docker_import(self):
        with tempfile.TemporaryDirectory() as temp:
            package, _ = self.build_signed(Path(temp))
            fake_expected = "sha256:" + "d" * 64
            (package / "notice-manifest.json").write_text(json.dumps({"schema":"volt-notice-inventory/v1", "image_id":fake_expected, "platform":"linux/amd64"})+"\n")
            scan_doc = json.loads((package / "release-scan.json").read_text()); scan_doc["Metadata"]["ImageID"] = fake_expected
            (package / "release-scan.json").write_text(json.dumps(scan_doc)+"\n")
            manifest = archive.build_manifest(package, "0.1.0-rc.1", self.source_sha, self.image_id,
                "linux/amd64", archive.EXPECTED_IDENTITY, archive.EXPECTED_ISSUER, "sha256:" + "c" * 64)
            manifest["image_id"] = fake_expected
            (package / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
            with patch.object(sys, "argv", ["archive.py", "sign", "--directory", str(package), "--key", str(self.key)]):
                self.assertEqual(archive.main(), 0)
            packed = Path(temp) / "mismatch.tar"
            archive.create_archive(package, packed)
            docker_calls = []
            real_run = subprocess.run
            real_check_output = subprocess.check_output
            def run(command, *args, **kwargs):
                if command[:2] == ["docker", "image"]:
                    docker_calls.append(command)
                    return subprocess.CompletedProcess(command, 0, stdout="Loaded image ID: sha256:" + "d" * 64 + "\n", stderr="")
                return real_run(command, *args, **kwargs)
            def check_output(command, *args, **kwargs):
                if command[:3] == ["docker", "image", "inspect"]:
                    return json.dumps([{"Id": "sha256:" + "d" * 64}])
                return real_check_output(command, *args, **kwargs)
            with patch.object(archive.subprocess, "run", side_effect=run), patch.object(archive.subprocess, "check_output", side_effect=check_output):
                with patch.object(sys, "argv", ["archive.py", "load", "--archive", str(packed), "--test-public-key", str(self.public), "--docker", "docker"]):
                    self.assertEqual(archive.main(), 2)
            self.assertEqual(docker_calls, [])

    def test_verified_archive_loads_only_the_manifest_image_and_labels(self):
        with tempfile.TemporaryDirectory() as temp:
            _, packed = self.build_signed(Path(temp))
            inspected = [{"Id": self.image_id, "Os": "linux", "Architecture": "amd64",
                          "Config": {"Labels": {"org.opencontainers.image.revision": self.source_sha,
                                                  "org.opencontainers.image.version": "0.1.0-rc.1"}}}]
            real_run = subprocess.run
            real_check_output = subprocess.check_output
            docker_calls = []
            def run(command, *args, **kwargs):
                if command[:4] == ["docker", "image", "load", "--input"]:
                    docker_calls.append(command)
                    return subprocess.CompletedProcess(command, 0, stdout=f"Loaded image ID: {self.image_id}\n", stderr="")
                return real_run(command, *args, **kwargs)
            def check_output(command, *args, **kwargs):
                if command[:3] == ["docker", "image", "inspect"]: return json.dumps(inspected)
                return real_check_output(command, *args, **kwargs)
            with patch.object(archive.subprocess, "run", side_effect=run), patch.object(archive.subprocess, "check_output", side_effect=check_output):
                with patch.object(sys, "argv", ["archive.py", "load", "--archive", str(packed), "--test-public-key", str(self.public), "--docker", "docker"]):
                    self.assertEqual(archive.main(), 0)
            self.assertEqual(len(docker_calls), 1)

    def test_safe_extractor_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            malicious = temp / "bad.tar"
            with tarfile.open(malicious, "w") as tar:
                info = tarfile.TarInfo("../escaped")
                info.size = 1
                import io
                tar.addfile(info, io.BytesIO(b"x"))
            with self.assertRaisesRegex(ValueError, "unsafe"):
                archive.safe_extract(malicious, temp / "out")

    def test_actual_verifier_rejects_unsigned_extra_even_if_checksums_are_recomputed(self):
        with tempfile.TemporaryDirectory() as temp:
            _, packed = self.build_signed(Path(temp))
            extracted = Path(temp) / "consumer"
            extracted.mkdir(); archive.safe_extract(packed, extracted)
            (extracted / "unreviewed-extra.sh").write_text("echo unreviewed\n")
            rows = []
            for item in sorted(p for p in extracted.rglob("*") if p.is_file() and p.relative_to(extracted).as_posix() != "SHA256SUMS"):
                rows.append(f"{archive.sha(item)}  {item.relative_to(extracted).as_posix()}")
            (extracted / "SHA256SUMS").write_text("\n".join(rows) + "\n")
            repacked = Path(temp) / "unsigned-extra.tar"; archive.create_archive(extracted, repacked)
            with patch.object(sys, "argv", ["archive.py", "verify", "--archive", str(repacked), "--test-public-key", str(self.public)]):
                self.assertEqual(archive.main(), 2)

    def test_actual_verifier_rejects_archive_supplied_sigstore_root(self):
        with tempfile.TemporaryDirectory() as temp:
            package, _ = self.build_signed(Path(temp))
            (package / "trusted_root.json").write_text('{"root":"attacker-selected"}\n')
            manifest = archive.build_manifest(package, "0.1.0-rc.1", self.source_sha, self.image_id,
                "linux/amd64", archive.EXPECTED_IDENTITY, archive.EXPECTED_ISSUER, "sha256:"+"c"*64)
            (package / "manifest.json").write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n")
            with patch.object(sys,"argv",["archive.py","sign","--directory",str(package),"--key",str(self.key)]): self.assertEqual(archive.main(),0)
            packed=Path(temp)/"root-substitution.tar"; archive.create_archive(package,packed)
            with patch.object(sys,"argv",["archive.py","verify","--archive",str(packed),"--test-public-key",str(self.public)]):
                self.assertEqual(archive.main(),2)

    def test_signed_cross_file_registry_digest_disagreement_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            package, _ = self.build_signed(Path(temp))
            (package / "registry-digest.txt").write_text("sha256:" + "e" * 64 + "\n")
            manifest = archive.build_manifest(package, "0.1.0-rc.1", self.source_sha, self.image_id,
                "linux/amd64", archive.EXPECTED_IDENTITY, archive.EXPECTED_ISSUER, "sha256:" + "c" * 64)
            (package / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
            with patch.object(sys, "argv", ["archive.py", "sign", "--directory", str(package), "--key", str(self.key)]): self.assertEqual(archive.main(), 0)
            with self.assertRaisesRegex(ValueError, "registry digest file disagrees"):
                archive.verify_directory(package, "cosign", public_key=self.public)

    def test_production_trust_root_must_match_out_of_band_pin(self):
        with tempfile.TemporaryDirectory() as temp:
            package, _ = self.build_signed(Path(temp))
            untrusted = Path(temp) / "attacker-root.json"; untrusted.write_text('{"root":"attacker"}')
            with self.assertRaisesRegex(ValueError, "out-of-band SHA-256"):
                archive.verify_directory(package, "cosign", trusted_root=untrusted, trusted_root_sha256="0" * 64)
            with patch.object(archive, "run") as cosign:
                archive.verify_directory(package, "cosign", trusted_root=untrusted, trusted_root_sha256=archive.sha(untrusted))
                command = cosign.call_args.args[0]
                self.assertIn(str(untrusted), command)
                self.assertNotIn(str(package / "trusted_root.json"), command)

    def test_corrupt_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            broken = Path(temp) / "corrupt.tar"
            broken.write_bytes(b"not a tar archive")
            with self.assertRaises(tarfile.ReadError):
                archive.safe_extract(broken, Path(temp) / "out")

    def test_actual_oci_consumer_accepts_gzip_layer_and_keeps_index_config_ids_distinct(self):
        import io
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); package, _ = self.build_signed(root); image = root / "oci.tar"
            source = self.source_sha
            raw_layer = b"valid fixture uncompressed layer bytes"
            compressed = gzip.compress(raw_layer, mtime=0)
            config = {"os":"linux", "architecture":"amd64", "created":"1970-01-01T00:00:00Z", "config":{"Labels":{
                "org.opencontainers.image.revision":source,"org.opencontainers.image.version":"0.1.0-rc.1"}},
                "rootfs":{"type":"layers","diff_ids":["sha256:"+hashlib.sha256(raw_layer).hexdigest()]}}
            config_bytes = json.dumps(config,sort_keys=True,separators=(",",":")).encode()
            blobs = {}
            def descriptor(data, media):
                digest=hashlib.sha256(data).hexdigest(); blobs["blobs/sha256/"+digest]=data
                return {"mediaType":media,"digest":"sha256:"+digest,"size":len(data)}
            repository_data = b'{}'
            def write_layout(index_data, compat_data, extra_blobs=None, repository_override=None):
                if isinstance(index_data, dict): index_data=json.dumps(index_data).encode()
                entries={"oci-layout":b'{"imageLayoutVersion":"1.0.0"}',"index.json":index_data,
                         "manifest.json":json.dumps([compat_data]).encode(),"repositories":repository_override or repository_data,
                         **blobs,**(extra_blobs or {})}
                with tarfile.open(image,"w") as tf:
                    for name,data in entries.items():
                        info=tarfile.TarInfo(name); info.size=len(data); tf.addfile(info,io.BytesIO(data))
            cfg=descriptor(config_bytes,"application/vnd.oci.image.config.v1+json")
            layer=descriptor(compressed,"application/vnd.oci.image.layer.v1.tar+gzip")
            compat={"Config":"blobs/sha256/"+cfg["digest"].removeprefix("sha256:"),"Layers":["blobs/sha256/"+layer["digest"].removeprefix("sha256:")],"RepoTags":["volt:fixture"]}
            image_manifest=json.dumps({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":cfg,"layers":[layer]},sort_keys=True,separators=(",",":")).encode()
            image_desc=descriptor(image_manifest,"application/vnd.oci.image.manifest.v1+json")
            index=json.dumps({"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{**image_desc,"platform":{"os":"linux","architecture":"amd64"},"annotations":{"io.containerd.image.name":"volt:fixture"}}]},sort_keys=True,separators=(",",":")).encode()
            legacy_config={**archive._docker_zero_container_config(),**config["config"]}
            exporter_record={"created":config["created"],"container_config":archive._docker_zero_container_config(),"config":legacy_config,"architecture":"amd64","os":"linux"}
            def exporter_record_bytes(record):
                raw=json.dumps(record,separators=(",",":")).encode()
                fields=archive._raw_json_object_fields(raw)
                fields.pop("id",None)
                fields["layer_id"]=json.dumps(config["rootfs"]["diff_ids"][0],separators=(",",":")).encode()
                material=b"{"+b",".join(json.dumps(key).encode()+b":"+fields[key] for key in sorted(fields))+b"}"
                result={**record,"id":hashlib.sha256(material).hexdigest()}
                return result,json.dumps(result,separators=(",",":")).encode()
            exporter_record,metadata_bytes=exporter_record_bytes(exporter_record)
            metadata_name="blobs/sha256/"+hashlib.sha256(metadata_bytes).hexdigest()
            blobs[metadata_name]=metadata_bytes
            repository_data=json.dumps({"volt":{"fixture":config["rootfs"]["diff_ids"][0].removeprefix("sha256:")}}).encode()
            write_layout(index,compat)
            selected_id=image_desc["digest"]
            identity=archive.validate_docker_archive(image,{"image_id":selected_id,"source_commit":source,"version":"0.1.0-rc.1","platform":"linux/amd64"})
            self.assertEqual(identity["image_id"],selected_id)
            self.assertEqual(identity["image_config_id"],cfg["digest"])
            self.assertNotEqual(identity["image_id"],identity["image_config_id"])
            shutil.copyfile(image,package/"image.tar")
            notice=json.loads((package/"notice-manifest.json").read_text()); notice["image_id"]=selected_id
            (package/"notice-manifest.json").write_text(json.dumps(notice)+"\n")
            scan=json.loads((package/"release-scan.json").read_text()); scan["Metadata"]["ImageID"]=selected_id
            (package/"release-scan.json").write_text(json.dumps(scan)+"\n")
            release_manifest=archive.build_manifest(package,"0.1.0-rc.1",source,selected_id,"linux/amd64",archive.EXPECTED_IDENTITY,archive.EXPECTED_ISSUER,"sha256:"+"c"*64)
            (package/"manifest.json").write_text(json.dumps(release_manifest,sort_keys=True,indent=2)+"\n")
            with patch.object(sys,"argv",["archive.py","sign","--directory",str(package),"--key",str(self.key)]): self.assertEqual(archive.main(),0)
            oci_package=root/"oci-release.tar"
            archive.create_archive(package,oci_package)
            with patch.object(sys,"argv",["archive.py","verify","--archive",str(oci_package),"--test-public-key",str(self.public),"--source-sha",source,"--image-id",selected_id]):
                self.assertEqual(archive.main(),0)
            real_run, real_check_output = subprocess.run, subprocess.check_output
            def docker_run(command, *args, **kwargs):
                if command[:3] == ["docker", "image", "load"]:
                    return subprocess.CompletedProcess(command, 0, "Loaded image", "")
                return real_run(command, *args, **kwargs)
            def docker_inspect(command, *args, **kwargs):
                if command[:3] == ["docker", "image", "inspect"]:
                    image_id = docker_inspect.image_id
                    row = {"Id":image_id,"Os":"linux","Architecture":"amd64","Config":{"Labels":{
                        "org.opencontainers.image.revision":source,"org.opencontainers.image.version":"0.1.0-rc.1"}}}
                    return json.dumps([row]).encode()
                return real_check_output(command, *args, **kwargs)
            for returned_id in (selected_id, cfg["digest"]):
                docker_inspect.image_id = returned_id
                with patch("archive.subprocess.run", side_effect=docker_run), patch("archive.subprocess.check_output", side_effect=docker_inspect), \
                     patch.object(sys, "argv", ["archive.py","load","--archive",str(oci_package),"--test-public-key",str(self.public)]):
                    self.assertEqual(archive.main(), 0)
            docker_inspect.image_id = "sha256:" + "f" * 64
            with patch("archive.subprocess.run", side_effect=docker_run), patch("archive.subprocess.check_output", side_effect=docker_inspect), \
                 patch.object(sys, "argv", ["archive.py","load","--archive",str(oci_package),"--test-public-key",str(self.public)]):
                self.assertEqual(archive.main(), 2)
            if shutil.which("zstd"):
                compressed_zstd=subprocess.run(["zstd","-q","-c"],input=raw_layer,capture_output=True,check=True).stdout
                blobs.clear()
                cfg=descriptor(config_bytes,"application/vnd.oci.image.config.v1+json")
                layer=descriptor(compressed_zstd,"application/vnd.oci.image.layer.v1.tar+zstd")
                repository_data=json.dumps({"volt":{"fixture":config["rootfs"]["diff_ids"][0].removeprefix("sha256:")}}).encode()
                compat={"Config":"blobs/sha256/"+cfg["digest"].removeprefix("sha256:"),"Layers":["blobs/sha256/"+layer["digest"].removeprefix("sha256:")],"RepoTags":["volt:fixture"]}
                image_manifest=json.dumps({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":cfg,"layers":[layer]},sort_keys=True,separators=(",",":")).encode()
                image_desc=descriptor(image_manifest,"application/vnd.oci.image.manifest.v1+json")
                index=json.dumps({"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{**image_desc,"platform":{"os":"linux","architecture":"amd64"},"annotations":{"io.containerd.image.name":"volt:fixture"}}]},sort_keys=True,separators=(",",":")).encode()
                write_layout(index,compat)
                archive.validate_docker_archive(image,{"image_id":image_desc["digest"],"source_commit":source,"version":"0.1.0-rc.1","platform":"linux/amd64"})
            corrupt=json.loads(index); corrupt["manifests"][0]["size"]+=1
            write_layout(corrupt,compat)
            with self.assertRaisesRegex(ValueError,"size or digest mismatch"):
                archive.validate_docker_archive(image,{"image_id":selected_id,"source_commit":source,"version":"0.1.0-rc.1","platform":"linux/amd64"})
            contradictory=json.loads(index); contradictory["manifests"].append({**contradictory["manifests"][0],"platform":{"os":"linux","architecture":"arm64"}})
            write_layout(contradictory,compat)
            with self.assertRaisesRegex(ValueError,"contradictory platform"):
                archive.validate_docker_archive(image,{"image_id":selected_id,"source_commit":source,"version":"0.1.0-rc.1","platform":"linux/amd64"})
            wrong_ref={**compat,"RepoTags":["volt:other"]}; write_layout(index,wrong_ref)
            with self.assertRaisesRegex(ValueError,"image reference disagrees"):
                archive.validate_docker_archive(image,{"image_id":selected_id,"source_commit":source,"version":"0.1.0-rc.1","platform":"linux/amd64"})
            wrong_repo=json.loads(index)
            wrong_repo["manifests"][0]["annotations"]["io.containerd.image.name"]="evil/volt:fixture"
            write_layout(wrong_repo,compat)
            with self.assertRaisesRegex(ValueError,"image reference disagrees"):
                archive.validate_docker_archive(image,{"image_id":selected_id,"source_commit":source,"version":"0.1.0-rc.1","platform":"linux/amd64"})
            write_layout(index,compat,repository_override=b'{"evil":{"fixture":"'+layer["digest"].removeprefix("sha256:").encode()+b'"}}')
            with self.assertRaisesRegex(ValueError,"repositories map disagrees"):
                archive.validate_docker_archive(image,{"image_id":selected_id,"source_commit":source,"version":"0.1.0-rc.1","platform":"linux/amd64"})
            changed_metadata=dict(exporter_record); changed_metadata["id"]="b"*64
            changed_bytes=json.dumps(changed_metadata,separators=(",",":")).encode()
            blobs[metadata_name]=changed_bytes
            write_layout(index,compat)
            with self.assertRaisesRegex(ValueError,"content address mismatch"):
                archive.validate_docker_archive(image,{"image_id":selected_id,"source_commit":source,"version":"0.1.0-rc.1","platform":"linux/amd64"})
            blobs[metadata_name]=metadata_bytes
            foreign_record={**exporter_record,"id":hashlib.sha256(b"foreign-0").hexdigest()}
            foreign_bytes=json.dumps(foreign_record,separators=(",",":")).encode()
            del blobs[metadata_name]
            foreign_name="blobs/sha256/"+hashlib.sha256(foreign_bytes).hexdigest()
            blobs[foreign_name]=foreign_bytes
            write_layout(index,compat)
            with self.assertRaisesRegex(ValueError,"legacy layer ID does not derive"):
                archive.validate_docker_archive(image,{"image_id":selected_id,"source_commit":source,"version":"0.1.0-rc.1","platform":"linux/amd64"})
            del blobs[foreign_name]
            changed_config={**exporter_record,"config":{**exporter_record["config"],"Entrypoint":["/unrelated-entrypoint"]}}
            changed_config,changed_config_bytes=exporter_record_bytes(changed_config)
            changed_config_name="blobs/sha256/"+hashlib.sha256(changed_config_bytes).hexdigest()
            blobs[changed_config_name]=changed_config_bytes
            write_layout(index,compat)
            with self.assertRaisesRegex(ValueError,"final runtime config disagrees"):
                archive.validate_docker_archive(image,{"image_id":selected_id,"source_commit":source,"version":"0.1.0-rc.1","platform":"linux/amd64"})
            del blobs[changed_config_name]
            changed_container={**exporter_record,"container_config":{**exporter_record["container_config"],"unexpected":"data"}}
            changed_container,changed_container_bytes=exporter_record_bytes(changed_container)
            changed_container_name="blobs/sha256/"+hashlib.sha256(changed_container_bytes).hexdigest()
            blobs[changed_container_name]=changed_container_bytes
            write_layout(index,compat)
            with self.assertRaisesRegex(ValueError,"container_config is not the supported zero-value"):
                archive.validate_docker_archive(image,{"image_id":selected_id,"source_commit":source,"version":"0.1.0-rc.1","platform":"linux/amd64"})
            del blobs[changed_container_name]
            blobs[metadata_name]=metadata_bytes
            broken_record={**exporter_record,"parent":"f"*64}
            broken_bytes=json.dumps(broken_record,separators=(",",":")).encode()
            del blobs[metadata_name]
            broken_name="blobs/sha256/"+hashlib.sha256(broken_bytes).hexdigest()
            blobs[broken_name]=broken_bytes
            write_layout(index,compat)
            with self.assertRaisesRegex(ValueError,"legacy layer chain does not match selected layer order"):
                archive.validate_docker_archive(image,{"image_id":selected_id,"source_commit":source,"version":"0.1.0-rc.1","platform":"linux/amd64"})
            del blobs[broken_name]
            blobs[metadata_name]=metadata_bytes
            write_layout(index,compat,{"blobs/sha256/"+"f"*64:b"extra"})
            with self.assertRaisesRegex(ValueError,"unreferenced image blobs"):
                archive.validate_docker_archive(image,{"image_id":selected_id,"source_commit":source,"version":"0.1.0-rc.1","platform":"linux/amd64"})

    def test_actual_consumer_authenticates_hashes_before_source_bundle_git_checkout(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); package,_=self.build_signed(root)
            # Replace the signed bundle with an attacker-shaped default branch. Its advertised
            # commit still includes the signed commit, but its bytes no longer match inventory.
            source_repo=root/"source-repo"
            subprocess.run(["git","-C",str(source_repo),"checkout","--quiet","-b","attacker-default"],check=True,capture_output=True)
            (source_repo/".gitattributes").write_text("attacker.txt filter=sentinel\n")
            (source_repo/"attacker.txt").write_text("trigger\n")
            subprocess.run(["git","-C",str(source_repo),"add",".gitattributes","attacker.txt"],check=True)
            env={**os.environ,"GIT_AUTHOR_NAME":"Fixture","GIT_AUTHOR_EMAIL":"fixture@example.invalid","GIT_COMMITTER_NAME":"Fixture","GIT_COMMITTER_EMAIL":"fixture@example.invalid"}
            subprocess.run(["git","-C",str(source_repo),"commit","-m","attacker default"],check=True,env=env,capture_output=True)
            subprocess.run(["git","-C",str(source_repo),"bundle","create",str(package/"source.bundle"),"HEAD","main"],check=True,capture_output=True)
            sentinel=root/"FILTER-RAN"
            git_config=root/"gitconfig"
            git_config.write_text(f"[filter \"sentinel\"]\n\tsmudge = touch {sentinel}\n\tclean = cat\n\trequired = true\n")
            with patch.dict(os.environ,{"GIT_CONFIG_GLOBAL":str(git_config)}):
                with self.assertRaisesRegex(ValueError,"digest mismatch"):
                    archive.verify_directory(package,"cosign",public_key=self.public)
                damaged=json.loads((package/"signature.bundle").read_text())
                damaged["signature_b64"]=base64.b64encode(b"invalid signature bytes").decode()
                (package/"signature.bundle").write_text(json.dumps(damaged)+"\n")
                with self.assertRaises(subprocess.CalledProcessError):
                    archive.verify_directory(package,"cosign",public_key=self.public)
            self.assertFalse(sentinel.exists(),"unverified bundle checkout invoked its filter")

    def test_signed_archive_rejects_contradictory_volt_source_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); package,_=self.build_signed(root)
            predicate=json.loads((package/"provenance.json").read_text())
            predicate["buildDefinition"]["externalParameters"]["source"]["ref"]="e"*40
            predicate["buildDefinition"]["resolvedDependencies"].append({"uri":"git+https://example.invalid/unrelated","digest":{"gitCommit":self.source_sha}})
            (package/"provenance.json").write_text(json.dumps(predicate)+"\n")
            manifest=archive.build_manifest(package,"0.1.0-rc.1",self.source_sha,self.image_id,"linux/amd64",archive.EXPECTED_IDENTITY,archive.EXPECTED_ISSUER,"sha256:"+"c"*64)
            (package/"manifest.json").write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n")
            with patch.object(sys,"argv",["archive.py","sign","--directory",str(package),"--key",str(self.key)]): self.assertEqual(archive.main(),0)
            with self.assertRaisesRegex(ValueError,"source URI/ref"):
                archive.verify_directory(package,"cosign",public_key=self.public)


if __name__ == "__main__":
    unittest.main()
