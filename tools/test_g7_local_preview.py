"""Focused safety checks for the local preview launcher."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("g7_local_preview", Path(__file__).with_name("g7_local_preview.py"))
preview = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preview)


class LocalPreviewSafetyTests(unittest.TestCase):
    def test_instance_name_is_safe_and_scoped(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
            self.assertEqual(preview.state_dir("demo"), Path(temp) / "volt/g7-preview/demo")
            for bad in ("../demo", "a/b", "demo space", ""):
                with self.subTest(bad=bad), self.assertRaises(SystemExit):
                    preview.state_dir(bad)

    def test_generated_secret_is_private_and_not_printed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "secret"
            value = preview.secret(path, 12)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.read_text().strip(), value)
            self.assertGreaterEqual(len(value), 16)

    def test_destroy_targets_only_resources_with_exact_instance_label(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
            root = preview.state_dir("demo")
            root.mkdir(parents=True)
            metadata = {"container": "volt-g7-preview-demo", "volumes": {
                "postgres": "volt-g7-preview-demo-postgres", "media": "volt-g7-preview-demo-media",
                "state": "volt-g7-preview-demo-state"}}
            (root / "instance.json").write_text(json.dumps(metadata))
            args = type("Args", (), {"instance": "demo"})()
            calls = []

            def fake_run(*command, capture=False):
                calls.append(command)
                if command[1:3] == ("ps", "-a") or command[1:3] == ("volume", "ls"):
                    return command[4][5:]
                if command[1:3] == ("inspect", "--format") or command[1:3] == ("volume", "inspect"):
                    return "demo"
                return ""

            with patch.object(preview, "run", side_effect=fake_run):
                preview.destroy(args)
            self.assertEqual(calls[0], ("docker", "ps", "-a", "--filter",
                "name=volt-g7-preview-demo", "--format", "{{.Names}}"))
            removed = [call[-1] for call in calls if len(call) >= 3 and call[1:3] == ("volume", "rm")]
            self.assertEqual(removed, list(metadata["volumes"].values()))
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
