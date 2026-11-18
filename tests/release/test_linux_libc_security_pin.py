from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXED_VERSION = "6.12.117-1"
FIXED_DEB_SHA256 = "8b4848725a2705e5b1612f2135c44300716690ba762368ab87df127e9a5ed416"


class LinuxLibcSecurityPinTests(unittest.TestCase):
    def setUp(self):
        self.lock = dict(
            line.split("=", 1)
            for line in (ROOT / "docker/g7/versions.lock").read_text().splitlines()
            if line and not line.startswith("#") and "=" in line
        )
        self.catalog = json.loads((ROOT / "tools/notices/debian-source-catalog.json").read_text())

    def test_fixed_security_binary_pin_is_exact_and_shared_for_both_architectures(self):
        version, digest = self.lock["os_delta_package_linux-libc-dev"].split("|", 1)
        self.assertEqual(version, FIXED_VERSION)
        self.assertEqual(digest, FIXED_DEB_SHA256)
        self.assertNotIn("os_delta_package_linux-libc-dev:amd64", self.lock)
        self.assertNotIn("os_delta_package_linux-libc-dev:arm64", self.lock)

    def test_linux_notice_source_closure_matches_fixed_binary_source_version(self):
        group, = [item for item in self.catalog["groups"] if item["source_package"] == "linux"]
        self.assertEqual(group["source_version"], FIXED_VERSION)
        self.assertEqual(group["dsc_sha256"],
            "041c7af261546dbad4ee57ccb237f02a8697b762be34aed2e1617ed49595942a")
        self.assertEqual(group["immutable_dsc_sha1"],
            "7b96c2cad4a8256df4233057d03252c3d10cf4b2")
        self.assertEqual(
            {item["filename"]: item["sha256"] for item in group["source_files"]},
            {
                "linux_6.12.117.orig.tar.xz":
                    "77cf7a48a73aeaa7cf4f94cb6d17f8fe545bf33a5dd8a56d6428db3a54645c74",
                "linux_6.12.117-1.debian.tar.xz":
                    "e3f3bec0723f780d9ef2a2b3215aea25d34c61cd884f1f858c9708a846c4f8f9",
            },
        )
        self.assertEqual(group["copyright_files"], [{
            "path": "/usr/share/doc/linux-libc-dev/copyright",
            "sha256": "2ae27ed8a5581e2cc4969c266e655a280a8982f87dfe72c011c3f03d91897076",
        }])

    def test_docker_download_install_and_delta_guards_remain_strict(self):
        dockerfile = (ROOT / "Dockerfile.g7").read_text()
        self.assertIn('apt-get download -qq "$package=$version"', dockerfile)
        self.assertIn('printf \'%s  %s\\n\' "$digest" "$deb" | sha256sum -c -', dockerfile)
        self.assertIn('apt-get install -yqq --no-install-recommends $packages', dockerfile)
        self.assertIn('actual=$(dpkg-query -W -f=\'${Version}\' "$package"); test "$actual" = "$expected"', dockerfile)
        self.assertIn('diff -u /tmp/g7-packages-expected /tmp/g7-packages-added-or-upgraded', dockerfile)
        self.assertIn('test ! -s /tmp/g7-packages-removed', dockerfile)


if __name__ == "__main__":
    unittest.main()
