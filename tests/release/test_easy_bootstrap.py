from __future__ import annotations

import unittest
from pathlib import Path
import subprocess

from tools.release.easy_bootstrap import COSIGN_IMAGE, ISSUER, SIGNER, VERSION, render_bootstrap

VERIFIER = "ghcr.io/njvenis/volt-installer-verifier@sha256:" + "a" * 64


class EasyBootstrapTests(unittest.TestCase):
    def render(self, *, version: str = VERSION, signer: str = SIGNER,
               issuer: str = ISSUER, verifier_image: str = VERIFIER) -> str:
        return render_bootstrap(version=version, signer=signer, issuer=issuer,
                                verifier_image=verifier_image)

    def test_verifies_exact_launcher_before_execution_with_read_only_package(self) -> None:
        command = self.render()
        verify_at = command.index("verify-blob")
        execute_at = command.index('sh "$verify_dir/launcher.sh"')
        self.assertLess(verify_at, execute_at)
        self.assertIn("--read-only --cap-drop=ALL", command)
        self.assertIn("--env HOME=/tmp", command)
        self.assertIn('src=$verify_dir,dst=/package,readonly', command)
        self.assertIn('cat ./launcher.sh > "$verify_dir/launcher.sh"', command)
        self.assertIn("launcher.sigstore.json", command)
        self.assertIn('cat ./installer.bundle.tar.gz > "$verify_dir/installer.bundle.tar.gz"', command)
        self.assertIn('cat ./installer.bundle.sigstore.json > "$verify_dir/installer.bundle.sigstore.json"', command)
        self.assertIn('sh "$verify_dir/launcher.sh" install', command)
        self.assertIn(SIGNER, command)
        self.assertIn(ISSUER, command)
        self.assertIn(COSIGN_IMAGE, command)
        self.assertIn(VERIFIER, command)
        self.assertIn('VOLT_EXPECTED_VERIFIER_IMAGE=' + VERIFIER, command)
        self.assertNotIn("curl", command)
        self.assertNotIn("eval", command)
        self.assertNotIn("/var/run/docker.sock", command)
        self.assertNotIn("insecure-ignore", command)
        syntax = subprocess.run(["sh", "-n"], input=command, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_rejects_non_rc4_or_non_main_identity(self) -> None:
        with self.assertRaises(ValueError):
            self.render(version="0.1.0-rc.3")
        with self.assertRaises(ValueError):
            self.render(signer=SIGNER.replace("refs/heads/main", "refs/tags/v0.1.0-rc.4"))
        with self.assertRaises(ValueError):
            self.render(verifier_image="VOLT_VERIFIER_IMAGE_REFERENCE")
        with self.assertRaises(ValueError):
            self.render(verifier_image="127.0.0.1:46150/volt-installer-verifier@sha256:" + "b" * 64)

    def test_official_verifier_pin_is_recorded_in_release_tool_lock(self) -> None:
        lock = Path(__file__).resolve().parents[2] / "tools/release/tools.lock"
        entries = dict(line.split("=", 1) for line in lock.read_text().splitlines()
                       if "=" in line and not line.startswith("#"))
        self.assertEqual(entries["cosign_version"], "3.1.4")
        self.assertEqual(entries["cosign_official_oci_image"], COSIGN_IMAGE)


if __name__ == "__main__":
    unittest.main()
