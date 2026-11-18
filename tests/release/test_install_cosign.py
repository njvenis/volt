from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools.release import install_cosign


class CosignInstallerTests(unittest.TestCase):
    def test_fixed_native_platform_selection(self):
        cases = {
            ("Linux", "x86_64"): "linux_amd64",
            ("Linux", "aarch64"): "linux_arm64",
            ("Darwin", "arm64"): "darwin_arm64",
            ("Darwin", "x86_64"): "darwin_amd64",
        }
        for args, target in cases.items():
            with self.subTest(args=args):
                self.assertEqual(install_cosign.target_platform(*args), target)
        for args in (("Windows", "AMD64"), ("Darwin", "ppc64")):
            with self.subTest(args=args), self.assertRaises(SystemExit):
                install_cosign.target_platform(*args)

    def test_native_darwin_arm_download_uses_official_url_and_sha256_pin(self):
        content = b"pinned fixture binary"
        digest = __import__("hashlib").sha256(content).hexdigest()
        pins = {
            "cosign_version": "3.1.4",
            "cosign_release_template": "https://github.com/sigstore/cosign/releases/download/v{version}/cosign-{platform}",
            "cosign_darwin_arm64_sha256": digest,
        }
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "cosign"
            observed = {}
            def download(url, path):
                observed["url"] = url
                Path(path).write_bytes(content)
            with patch.object(install_cosign, "DEST", Path(temporary)), \
                 patch.object(install_cosign, "pin", side_effect=lambda key: pins[key]), \
                 patch.object(install_cosign, "target_platform", return_value="darwin_arm64"), \
                 patch.object(install_cosign.urllib.request, "urlretrieve", side_effect=download), \
                 patch.object(install_cosign.subprocess, "run", return_value=SimpleNamespace(stdout="Cosign v3.1.4\nline2\nline3\nline4\nline5\n")):
                install_cosign.main()
            self.assertEqual(observed["url"], "https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-darwin-arm64")
            self.assertEqual(destination.read_bytes(), content)
            self.assertTrue(destination.stat().st_mode & 0o111)


if __name__ == "__main__":
    unittest.main()
