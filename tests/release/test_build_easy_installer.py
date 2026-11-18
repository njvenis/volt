from __future__ import annotations

import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path

from tools.build_compose_bundle import build as build_bundle
from tools.release.build_easy_installer import FILES, build


ROOT = Path(__file__).resolve().parents[2]
IMAGE = "ghcr.io/njvenis/volt@sha256:" + "c" * 64
VERIFIER = "ghcr.io/njvenis/volt-installer-verifier@sha256:" + "d" * 64


class EasyInstallerPackageTests(unittest.TestCase):
    def test_outer_package_uses_the_exact_launcher_from_the_closed_signed_bundle(self):
        with tempfile.TemporaryDirectory(prefix="volt-easy-outer-package-") as directory:
            root = Path(directory)
            source = root / "source"
            (source / "deploy").mkdir(parents=True)
            shutil.copytree(ROOT / "deploy/compose", source / "deploy/compose")
            (source / "deploy/compose/VERSION").write_text("0.1.0-rc.4\n")
            with (source / "deploy/compose/README.rc4.md").open("a") as readme:
                readme.write("\nCandidate source root fixture.\n")
            bundle = root / "bundle.tar.gz"
            build_bundle(bundle, IMAGE, source, verifier_reference=VERIFIER)
            launcher_signature = root / "launcher.sigstore.json"
            bundle_signature = root / "bundle.sigstore.json"
            launcher_signature.write_text("fixture detached signature bundle\n")
            bundle_signature.write_text("fixture detached signature bundle\n")
            output = root / "small-package.tar.gz"
            build(output, bundle=bundle, launcher_signature=launcher_signature,
                  bundle_signature=bundle_signature, verifier_reference=VERIFIER,
                  source_root=source)
            with tarfile.open(bundle, "r:gz") as archive:
                expected_launcher = archive.extractfile(next(m for m in archive.getmembers()
                    if Path(m.name).name == "launcher.sh")).read()
            with tarfile.open(output, "r:gz") as package:
                members = package.getmembers()
                self.assertEqual(tuple(m.name for m in members), FILES)
                actual_launcher = package.extractfile("launcher.sh").read()
            self.assertEqual(actual_launcher, expected_launcher)

    def test_outer_package_rejects_fixture_registry_verifier_reference(self):
        with tempfile.TemporaryDirectory(prefix="volt-easy-outer-package-reject-") as directory:
            root = Path(directory)
            source = root / "source"
            (source / "deploy").mkdir(parents=True)
            shutil.copytree(ROOT / "deploy/compose", source / "deploy/compose")
            (source / "deploy/compose/VERSION").write_text("0.1.0-rc.4\n")
            bundle = root / "bundle.tar.gz"
            build_bundle(bundle, IMAGE, source, verifier_reference=VERIFIER)
            signature = root / "signature.json"
            signature.write_text("fixture\n")
            with self.assertRaisesRegex(SystemExit, "official verifier digest"):
                build(root / "must-not-exist.tar.gz", bundle=bundle,
                      launcher_signature=signature, bundle_signature=signature,
                      verifier_reference="127.0.0.1:46150/volt-installer-verifier@sha256:" + "e" * 64)


if __name__ == "__main__":
    unittest.main()
