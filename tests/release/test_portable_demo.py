"""Local-demo archive integrity and platform admission tests."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "release"))
from tools.release import portable_demo


def make_image(directory: Path, architecture: str = "arm64") -> tuple[Path, str, str]:
    layer_io = io.BytesIO()
    with tarfile.open(fileobj=layer_io, mode="w"):
        pass
    layer = layer_io.getvalue()
    revision = "a" * 40
    source_tar = directory / "source.tar"
    with tarfile.open(source_tar, "w") as source:
        payload = b"fixture source archive\n"
        info = tarfile.TarInfo("README.txt")
        info.size = len(payload)
        source.addfile(info, io.BytesIO(payload))
    snapshot = "sha256:" + hashlib.sha256(source_tar.read_bytes()).hexdigest()
    config = {"os": "linux", "architecture": architecture, "config": {"Labels": {
        "org.opencontainers.image.revision": revision,
        "org.opencontainers.image.version": portable_demo.VERSION,
        "org.volt.oidc-deployment-modes": "demo,external",
        "org.volt.compose.install.contract": "1",
        "org.volt.compose-install.contract": "1",
        "org.volt.compose.source-snapshot": snapshot}},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()]}}
    config_bytes = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
    image_id = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    image_tar = directory / "image.tar"
    with tarfile.open(image_tar, "w") as image:
        entries = [(image_id.removeprefix("sha256:") + ".json", config_bytes), ("layer.tar", layer),
                   ("manifest.json", json.dumps([{"Config": image_id.removeprefix("sha256:") + ".json",
                                                   "RepoTags": [f"volt-portable-demo:{architecture}"],
                                                   "Layers": ["layer.tar"]}]).encode())]
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            image.addfile(info, io.BytesIO(data))
    return image_tar, revision, snapshot


class PortableDemoArchiveTest(unittest.TestCase):
    def package(self, root: Path, architecture: str = "arm64") -> Path:
        image_tar, revision, snapshot = make_image(root, architecture)
        with tarfile.open(image_tar) as image:
            config_name = json.loads(image.extractfile("manifest.json").read())[0]["Config"]
        image_id = "sha256:" + config_name.removesuffix(".json")
        manifest = portable_demo._manifest_for_image(
            image_tar, root / "source.tar", image_id, f"linux/{architecture}", revision, snapshot,
            f"volt-portable-demo:{architecture}")
        (root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        portable_demo._write_sums(root)
        result = root / "demo.tar.gz"
        portable_demo._pack_directory(root, result)
        return result

    def test_arm64_demo_archive_verifies_with_explicit_checksum_only_label(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            package = self.package(Path(temp))
            result = portable_demo.verify(package)
            self.assertEqual(result["platform"], "linux/arm64")
            self.assertEqual(result["integrity"], "checksum-only-local-demo")

    def test_native_workflow_is_read_only_and_scoped_to_portable_demo_branch(self) -> None:
        workflow = (ROOT / ".github/workflows/portable-demo.yml").read_text()
        self.assertIn("demo/portable-install", workflow)
        self.assertIn("ubuntu-24.04-arm", workflow)
        self.assertIn("ubuntu-24.04", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("docker push", workflow)
        self.assertRegex(workflow, r"actions/checkout@[0-9a-f]{40}")
        self.assertRegex(workflow, r"actions/upload-artifact@[0-9a-f]{40}")

    def test_changed_image_bytes_fail_checksum_admission(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = self.package(root)
            extracted = root / "unpacked"
            extracted.mkdir()
            import archive
            archive.safe_extract(package, extracted)
            image = extracted / f"volt-portable-demo-{portable_demo.VERSION}" / "image.tar"
            image.write_bytes(image.read_bytes() + b"tamper")
            changed = root / "changed.tar.gz"
            portable_demo._pack_directory(image.parent, changed)
            with self.assertRaisesRegex(ValueError, "checksum"):
                portable_demo.verify(changed)


if __name__ == "__main__":
    unittest.main()
