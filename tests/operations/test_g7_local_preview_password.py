from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools import g7_local_preview as preview


class LocalPreviewPasswordTests(unittest.TestCase):
    def test_init_stores_only_private_salted_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            args = SimpleNamespace(instance="preview", api_port=8180, oidc_port=8190,
                admin_username="preview-admin", admin_password_file=None)
            with patch.object(preview, "state_dir", return_value=root), \
                 patch("tools.g7_local_preview.getpass.getpass", side_effect=["correct horse battery staple", "correct horse battery staple"]), \
                 patch.object(preview, "make_tls"), \
                 patch.object(preview, "run", side_effect=["", "a" * 40]):
                preview.initialize(args)
            credential = root / "secrets" / "demo-admin-credentials"
            value = json.loads(credential.read_text())
            self.assertEqual(value["schema"], "uvm.demo-credential.v1")
            self.assertEqual(value["username"], "preview-admin")
            self.assertNotIn("correct horse battery staple", credential.read_text())
            self.assertEqual(credential.stat().st_mode & 0o777, 0o600)
            self.assertEqual((root.stat().st_mode & 0o777), 0o700)

    def test_password_file_must_be_private_regular_and_nonempty(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "password"
            path.write_text("long-password-value\n")
            path.chmod(0o644)
            with self.assertRaisesRegex(SystemExit, "private file"):
                preview.private_password_file(path)
            path.chmod(0o600)
            self.assertEqual(preview.private_password_file(path), "long-password-value")

    def test_smoke_passes_file_and_username_without_reading_secret_into_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            info = {"api_port": 8180, "oidc_port": 8190}
            password = root / "private-password"
            password.write_text("a-long-preview-password\n")
            password.chmod(0o600)
            args = SimpleNamespace(instance="preview", evidence=str(evidence),
                readback=True, admin_username="preview-admin", password_file=str(password))
            with patch.object(preview, "load", return_value=(root, info)), \
                 patch.object(preview, "preflight"), patch.object(preview, "verify_private_ingress"), \
                 patch.object(preview.subprocess, "run") as invoke:
                preview.smoke(args)
            command = invoke.call_args.args[0]
            self.assertIn("--username", command)
            self.assertEqual(command[command.index("--username") + 1], "preview-admin")
            self.assertEqual(command[command.index("--password-file") + 1], str(password))
            self.assertNotIn("a-long-preview-password", " ".join(command))
            self.assertTrue(password.exists(), "caller-owned password file must survive both smoke stages")

    def test_prompted_smoke_password_file_is_removed_even_when_browser_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "secrets").mkdir()
            args = SimpleNamespace(instance="preview", evidence=str(root / "evidence"),
                readback=False, admin_username="preview-admin", password_file=None)
            with patch.object(preview, "load", return_value=(root, {"api_port": 8180, "oidc_port": 8190})), \
                 patch.object(preview, "preflight"), patch.object(preview, "verify_private_ingress"), \
                 patch("tools.g7_local_preview.getpass.getpass", return_value="a-long-preview-password"), \
                 patch.object(preview.subprocess, "run", side_effect=RuntimeError("browser failed")):
                with self.assertRaisesRegex(RuntimeError, "browser failed"):
                    preview.smoke(args)
            self.assertFalse((root / "secrets" / ".smoke-password").exists())


if __name__ == "__main__":
    unittest.main()
