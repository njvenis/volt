"""Keep the reviewed security-sensitive VOLT pins aligned with uv.lock."""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXPECTED_PINS = {
    "authlib": "1.9.5",
    "cryptography": "50.0.2",
}


class DependencyPinRegressionTest(unittest.TestCase):
    def test_security_pins_match_the_resolved_lock(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        lock = tomllib.loads((ROOT / "uv.lock").read_text())
        direct = {
            item.split("==", 1)[0].lower(): item.split("==", 1)[1]
            for item in project["project"]["dependencies"]
            if "==" in item
        }
        resolved = {package["name"]: package["version"] for package in lock["package"]}

        for name, expected in EXPECTED_PINS.items():
            with self.subTest(package=name):
                self.assertEqual(direct.get(name), expected)
                self.assertEqual(resolved.get(name), expected)

    def test_ce_children_and_native_package_hashes_are_pinned_per_supported_architecture(self) -> None:
        lines = (ROOT / "docker/g7/versions.lock").read_text().splitlines()
        values = dict(line.split("=", 1) for line in lines if "=" in line and not line.startswith("#"))
        self.assertEqual(values["defectdojo_ce_amd64"], "3.5.0@sha256:cb027c6e84adfe9cfe7de07863eeaae4a4375ff4420b7c41ea4e563631f4359e")
        self.assertEqual(values["defectdojo_ce_arm64"], "3.5.0@sha256:064525e2663a82b52fb8d24b72a769212184c00c3bc831b02e826699ba89e662")
        dockerfile = (ROOT / "Dockerfile.g7").read_text()
        self.assertIn("ARG CE_IMAGE=defectdojo/defectdojo-django@sha256:cb027c6e84adfe9cfe7de07863eeaae4a4375ff4420b7c41ea4e563631f4359e", dockerfile)
        self.assertIn("*:amd64) arch=amd64 ;; *:arm64) arch=arm64", dockerfile)
        package_pairs = {}
        for key, value in values.items():
            if key.startswith(("os_package_", "os_delta_package_")) and key.rsplit(":", 1)[-1] in {"amd64", "arm64"}:
                base, architecture = key.rsplit(":", 1)
                package_pairs.setdefault(base, {})[architecture] = value
                self.assertRegex(value, r"^.+\|[0-9a-f]{64}$")
        self.assertTrue(package_pairs)
        for package, pair in package_pairs.items():
            with self.subTest(package=package):
                self.assertEqual(set(pair), {"amd64", "arm64"})
                self.assertEqual(pair["amd64"].split("|", 1)[0], pair["arm64"].split("|", 1)[0])

    def test_runtime_image_does_not_ship_the_pip_installer(self) -> None:
        dockerfile = (ROOT / "Dockerfile.g7").read_text()
        builder, runtime = dockerfile.split("FROM ${CE_IMAGE} AS runtime", 1)
        self.assertIn("python -m pip install --no-cache-dir uv==0.12.18", builder)
        self.assertIn("site-packages')", runtime)
        self.assertIn("pip = site / 'pip'", runtime)
        self.assertIn("shutil.rmtree(pip, ignore_errors=True)", runtime)
        self.assertIn("pip-*.dist-info", runtime)


if __name__ == "__main__":
    unittest.main()
