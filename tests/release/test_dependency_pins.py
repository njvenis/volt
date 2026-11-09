"""Keep the reviewed security-sensitive VOLT pins aligned with uv.lock."""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXPECTED_PINS = {
    "authlib": "1.9.5",
    "cryptography": "50.0.1",
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
