from __future__ import annotations

import json
import hashlib
import os
import pty
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools import g7_local_preview as preview

ROOT = Path(__file__).resolve().parents[2]
RC1_SOURCE = "d6e7868091839fcf1374b45397d2aa2c5964f97c"


class LocalPreviewPasswordTests(unittest.TestCase):
    def run_hidden_prompt_cli(self, command, cwd, env, password):
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(cwd)
            os.execvpe(command[0], command, env)
        output = bytearray()
        prompts = (b"New local preview admin password", b"Confirm local preview admin password")
        sent = 0
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], 1)
            if ready:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    chunk = b""
                if chunk:
                    output.extend(chunk)
                    while sent < len(prompts) and prompts[sent] in output:
                        os.write(fd, password.encode("utf-8") + b"\n")
                        sent += 1
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited:
                return subprocess.CompletedProcess(command, os.waitstatus_to_exitcode(status),
                    output.decode(errors="replace"), "")
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        self.fail("hidden password prompts did not finish before timeout")

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

    def test_init_cli_from_outside_checkout_uses_hidden_prompts_without_password_file(self):
        password_value = "private-cli-test-password"
        with tempfile.TemporaryDirectory(prefix="volt-preview-cli-outside-") as directory:
            outer = Path(directory)
            checkout = outer / "checkout"
            state = outer / "xdg-state"
            cloned = subprocess.run(["git", "clone", "--quiet", "--local", "--no-hardlinks",
                str(ROOT), str(checkout)], cwd=outer, text=True, capture_output=True, check=False)
            self.assertEqual(cloned.returncode, 0, cloned.stderr)
            env = os.environ.copy()
            env.pop("PYTHONPATH", None)
            env["XDG_STATE_HOME"] = str(state)
            command = [sys.executable, str(checkout / "tools/g7_local_preview.py"),
                "init", "cli", "--api-port", "18180", "--oidc-port", "18190",
                "--admin-username", "external-admin"]
            result = self.run_hidden_prompt_cli(command, outer, env, password_value)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(password_value, result.stdout)
            credential = state / "volt/g7-preview/cli/secrets/demo-admin-credentials"
            record = json.loads(credential.read_text(encoding="utf-8"))
            self.assertEqual(record["schema"], "uvm.demo-credential.v1")
            self.assertEqual(record["username"], "external-admin")
            self.assertEqual(credential.stat().st_mode & 0o777, 0o600)
            self.assertEqual(hashlib.scrypt(password_value.encode(), salt=bytes.fromhex(record["salt"]),
                n=2**15, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024).hex(), record["password_hash"])

    def test_rc1_docs_match_the_actual_immutable_rc1_cli(self):
        old_helper = subprocess.run(["git", "show", f"{RC1_SOURCE}:tools/g7_local_preview.py"],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout
        with tempfile.TemporaryDirectory(prefix="volt-rc1-cli-contract-") as directory:
            checkout = Path(directory)
            helper = checkout / "g7_local_preview.py"
            helper.write_text(old_helper, encoding="utf-8")
            env = os.environ.copy(); env.pop("PYTHONPATH", None)
            init_help = subprocess.run([sys.executable, str(helper), "init", "--help"],
                cwd=checkout, env=env, text=True, capture_output=True, check=False)
            smoke_help = subprocess.run([sys.executable, str(helper), "smoke", "--help"],
                cwd=checkout, env=env, text=True, capture_output=True, check=False)
            self.assertEqual(init_help.returncode, 0, init_help.stderr)
            self.assertEqual(smoke_help.returncode, 0, smoke_help.stderr)
            self.assertNotIn("--admin-username", init_help.stdout)
            self.assertNotIn("--password-file", smoke_help.stdout)
            accepted = {"init": {"--api-port", "--oidc-port"},
                        "smoke": {"--evidence", "--readback"}}
            for document in (ROOT / "docs/installation.md", ROOT / "tools/release/launcher-guide.txt"):
                lines = document.read_text(encoding="utf-8").splitlines()
                for action, expected in accepted.items():
                    matches = [line.strip() for line in lines
                        if f"tools/g7_local_preview.py {action} rc1 " in line]
                    self.assertTrue(matches, f"missing RC1 {action} example in {document}")
                    for line in matches:
                        options = {token for token in line.split() if token.startswith("--")}
                        self.assertLessEqual(options, expected, f"unsupported RC1 options in: {line}")

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
            self.assertIn("--password-stdin", command)
            self.assertEqual(invoke.call_args.kwargs["input"], "a-long-preview-password")
            self.assertNotIn("a-long-preview-password", " ".join(command))
            self.assertTrue(password.exists(), "caller-owned password file must survive both smoke stages")

    def test_prompted_smoke_password_is_piped_without_creating_a_file_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "secrets").mkdir()
            args = SimpleNamespace(instance="preview", evidence=str(root / "evidence"),
                readback=False, admin_username="preview-admin", password_file=None)
            with patch.object(preview, "load", return_value=(root, {"api_port": 8180, "oidc_port": 8190})), \
                 patch.object(preview, "preflight"), patch.object(preview, "verify_private_ingress"), \
                 patch("tools.g7_local_preview.getpass.getpass", return_value="a-long-preview-password"), \
                 patch.object(preview.subprocess, "run", side_effect=RuntimeError("browser failed")) as invoke:
                with self.assertRaisesRegex(RuntimeError, "browser failed"):
                    preview.smoke(args)
            self.assertEqual(invoke.call_args.kwargs["input"], "a-long-preview-password")
            self.assertIn("--password-stdin", invoke.call_args.args[0])
            self.assertNotIn("a-long-preview-password", " ".join(invoke.call_args.args[0]))
            self.assertFalse((root / "secrets" / ".smoke-password").exists())


if __name__ == "__main__":
    unittest.main()
