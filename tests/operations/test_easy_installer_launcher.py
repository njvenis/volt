from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.compose_release_qualification import render_fixture_launcher


ROOT = Path(__file__).resolve().parents[2]


class EasyInstallerLauncherTests(unittest.TestCase):
    def test_production_launcher_is_posix_and_gates_runtime_execution_on_signed_admission(self):
        path = ROOT / "deploy/compose/launcher.sh"
        source = path.read_text()
        syntax = subprocess.run(("sh", "-n", str(path)), text=True, capture_output=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        self.assertLess(source.index("--bundle-only"), source.index('tar -xzf "$BUNDLE"'))
        self.assertNotIn('"$IMAGE_REF" -m uvm.installer.admission', source)
        self.assertLess(source.index("graph-admission.json"), source.index('tar -xzf "$BUNDLE"'))
        self.assertLess(source.index("--runtime-prepare"), source.index('locked_compose up -d'))
        self.assertIn("--network none --read-only --cap-drop=ALL", source)
        self.assertLess(source.index("remote Docker contexts are unsupported"), source.index('docker pull "$VERIFIER_IMAGE"'))
        self.assertIn('unix://*)', source)
        self.assertIn("--mount", source)
        self.assertNotIn("/var/run/docker.sock", source)
        self.assertNotIn("python3 ", source)
        self.assertNotIn("openssl ", source)
        self.assertNotIn("git ", source)

    def test_fixture_renderer_requires_an_independently_built_verifier_pin(self):
        source = ROOT / "deploy/compose/launcher.sh"
        original = hashlib.sha256(source.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory(prefix="volt-launch-render-") as directory:
            root = Path(directory)
            fixture = root / "fixture"
            fixture.mkdir()
            generated = root / "launcher.sh"
            with self.assertRaisesRegex(RuntimeError, "fixture verifier ref"):
                render_fixture_launcher(source, generated, fixture)
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), original)

    def test_fixture_renderer_refuses_to_mutate_an_unsigned_placeholder_launcher(self):
        source = ROOT / "deploy/compose/launcher.sh"
        original = hashlib.sha256(source.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory(prefix="volt-launch-pin-") as directory:
            root = Path(directory)
            fixture = root / "fixture"
            fixture.mkdir()
            (fixture / "verifier.ref").write_text(
                "127.0.0.1:46150/volt-installer-verifier@sha256:" + "a" * 64 + "\n")
            with self.assertRaisesRegex(RuntimeError, "already bind the external verifier digest"):
                render_fixture_launcher(source, root / "launcher.sh", fixture)
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), original)

    def test_launcher_restore_fence_fails_before_start_and_uses_closed_ingress_overlay(self):
        source = (ROOT / "deploy/compose/launcher.sh").read_text()
        start = source.split('elif [ "$ACTION" = start ]; then', 1)[1].split('elif [ "$ACTION" = stop ]; then', 1)[0]
        self.assertLess(start.index('RESTORE_IMPORTED'), start.index('locked_compose up -d'))
        self.assertIn('RESTORE_CAPABILITIES_REVOKED', start)
        self.assertIn('RESTORE_SESSIONS_REVOKED', start)
        self.assertIn('local-restore.yaml', source.split('locked_compose() {', 1)[1].split('\n}', 1)[0])
        for field in ("restore_pending", "restore_imported", "restore_capabilities_revoked", "restore_sessions_revoked"):
            self.assertIn(f"{field})", source)


if __name__ == "__main__":
    unittest.main()
