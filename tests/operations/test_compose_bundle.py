from __future__ import annotations

import subprocess
import tarfile
import tempfile
import unittest
import io
from pathlib import Path
from tools.build_compose_bundle import verify


ROOT = Path(__file__).resolve().parents[2]


class ComposeBundleTests(unittest.TestCase):
    def test_bundle_builds_source_free_and_verifies_every_file(self):
        with tempfile.TemporaryDirectory(prefix="volt-compose-bundle-") as directory:
            archive = Path(directory) / "volt-compose.tar.gz"
            subprocess.run(("python3", str(ROOT / "tools/build_compose_bundle.py"), "build",
                            "--output", str(archive)), check=True, capture_output=True, text=True)
            result = subprocess.run(("python3", str(ROOT / "tools/build_compose_bundle.py"), "verify",
                                     "--archive", str(archive)), check=True, capture_output=True, text=True)
            self.assertIn("verified_version=0.1.0-rc.2 files=8", result.stdout)
            self.assertTrue(Path(str(archive) + ".sha256").is_file())

    def test_release_bundle_binds_digest_pinned_image_into_manifest_and_instructions(self):
        image = "ghcr.io/njvenis/volt@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory(prefix="volt-compose-release-bundle-") as directory:
            archive = Path(directory) / "release.tar.gz"
            subprocess.run(("python3", str(ROOT / "tools/build_compose_bundle.py"), "build",
                            "--output", str(archive), "--image-reference", image), check=True,
                           capture_output=True, text=True)
            subprocess.run(("python3", str(ROOT / "tools/build_compose_bundle.py"), "verify",
                            "--archive", str(archive)), check=True, capture_output=True, text=True)
            with tarfile.open(archive, "r:gz") as bundle:
                files = {Path(member.name).name: bundle.extractfile(member).read()
                         for member in bundle.getmembers() if member.isfile()}
            manifest = __import__("json").loads(files["manifest.json"])
            self.assertEqual(manifest["bundle_version"], "0.1.0-rc.2")
            self.assertEqual(manifest["release_image"], image)
            self.assertIn(image.encode(), files["README.md"])

    def test_release_bundle_rejects_tag_reference_instead_of_immutable_digest(self):
        with tempfile.TemporaryDirectory(prefix="volt-compose-release-bundle-") as directory:
            with self.assertRaisesRegex(SystemExit, "exact VOLT GHCR sha256 digest"):
                from tools.build_compose_bundle import build
                build(Path(directory) / "invalid.tar.gz", "ghcr.io/njvenis/volt:0.1.0-rc.2")

    def test_bundle_verifier_rejects_duplicate_and_traversal_members(self):
        for entries, message in (([("root/a", b"a"), ("root/a", b"b")], "duplicate"),
                                 ([("root/../outside", b"x")], "unsafe")):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                archive_path = Path(directory) / "bad.tar.gz"
                with tarfile.open(archive_path, "w:gz") as archive:
                    for name, data in entries:
                        item = tarfile.TarInfo(name); item.size = len(data)
                        archive.addfile(item, io.BytesIO(data))
                with self.assertRaisesRegex(SystemExit, message):
                    verify(archive_path)


class ComposeRecoveryTests(unittest.TestCase):
    def test_established_backup_provisions_offline_with_compose_identity(self):
        from deploy.compose import setup
        from unittest.mock import patch
        from types import SimpleNamespace
        import json
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            info = {"established": True, "project": "volt-compose-test", "owner_token": "test",
                    "image": "sha256:test", "image_admission": {"id": "sha256:test"}, "mode": "demo",
                    "subnet": "10.240.0.0/28", "gateway": "10.240.0.1",
                    "backup_inventory": {"postgres": {"postgres_version": "18"}, "media": {}, "state": {}}}
            with patch.object(setup, "load_instance", return_value=(root, info)), \
                 patch.object(setup, "check_any_resource", return_value=False), \
                 patch.object(setup, "resolved_compose"), \
                 patch.object(setup, "inspect_image", return_value=info["image_admission"]), \
                 patch.object(setup, "command") as run:
                setup.provision_restore(SimpleNamespace(directory=directory))
            calls = [call.args for call in run.call_args_list]
            self.assertEqual(len(calls), 4)
            self.assertTrue(all(call[1] in ("volume", "network") and call[2] == "create" for call in calls))
            self.assertTrue(all("com.docker.compose.project=volt-compose-test" in call for call in calls))
            self.assertIn("com.docker.compose.network=application", calls[-1])
            self.assertTrue(json.loads((root / "instance.json").read_text())["restore_pending"])

    def test_restore_accepts_captured_empty_store_and_rejects_changed_inventory(self):
        from deploy.compose import setup
        from unittest.mock import patch
        from types import SimpleNamespace
        info = {"project": "volt-compose-test", "restore_pending": True,
                "backup_inventory": {"postgres": {"postgres_version": "18", "sha256": "a", "entries": 10},
                                     "media": {"postgres_version": None, "sha256": "b", "entries": 0},
                                     "state": {"postgres_version": None, "sha256": "c", "entries": 0}}}
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(setup, "load_instance", return_value=(Path(directory), info)), \
                 patch.object(setup, "check_owned_resources"), \
                 patch.object(setup.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)), \
                 patch.object(setup, "volume_inventory", side_effect=lambda i, store: i["backup_inventory"][store]):
                setup.restore_admit(SimpleNamespace(directory=directory))
            self.assertTrue(info["restore_imported"])
            info["restore_imported"] = False
            with patch.object(setup, "load_instance", return_value=(Path(directory), info)), \
                 patch.object(setup, "check_owned_resources"), \
                 patch.object(setup.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)), \
                 patch.object(setup, "volume_inventory", return_value={"entries": 1}):
                with self.assertRaisesRegex(SystemExit, "differs from captured"):
                    setup.restore_admit(SimpleNamespace(directory=directory))

    def test_cold_stop_rejects_forced_exit_oom_and_missing_current_cleanup(self):
        from deploy.compose import setup
        from unittest.mock import patch
        import json
        clean = {"StartedAt": "2026-11-04T12:00:00Z", "ExitCode": 0}
        markers = "\n".join(("G7_STOP_PHASE=writers status=0", "G7_STOP_PHASE=workers status=0",
                             "G7_STOP_DATABASE_STOPPED service=postgresql", "G7_STOP_PHASE=databases status=0",
                             "G7_SHUTDOWN=controlled service_cleanup_status=0"))
        for state, logs, accepted in ((clean, markers, True), ({**clean, "ExitCode": 137}, markers, False),
                                      ({**clean, "OOMKilled": True}, markers, False), (clean, "", False),
                                      (clean, markers + "\nG7_STOP_ERROR", False),
                                      ({**clean, "ExitCode": 1}, markers, False)):
            with self.subTest(state=state, logs=logs), patch.object(setup, "command", side_effect=[json.dumps([{"State": state}]), logs]):
                if accepted:
                    setup.verify_cold_stop({"project": "volt-compose-test"})
                else:
                    with self.assertRaises(SystemExit):
                        setup.verify_cold_stop({"project": "volt-compose-test"})


if __name__ == "__main__":
    unittest.main()
