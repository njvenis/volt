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
import shutil
import subprocess

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
        installer = root / "installer.tar.gz"
        subprocess.run([sys.executable, str(ROOT / "tools/build_compose_bundle.py"), "build",
                        "--output", str(installer)], check=True, stdout=subprocess.DEVNULL)
        (root / "offline-tools").mkdir()
        for helper in (ROOT / "tools/release/portable_demo.py", ROOT / "tools/release/archive.py",
                       ROOT / "tools/release/provenance.py", ROOT / "tools/build_compose_bundle.py"):
            shutil.copyfile(helper, root / "offline-tools" / helper.name)
        (root / "PORTABLE-INSTALL.md").write_text(portable_demo._install_instructions())
        manifest["files"].update({p.relative_to(root).as_posix(): portable_demo.sha(p)
                                  for p in root.rglob("*") if p.is_file() and p.name != "source.tar"
                                  and p.name != "image.tar"})
        manifest["files"]["source.tar"] = portable_demo.sha(root / "source.tar")
        manifest["files"]["image.tar"] = portable_demo.sha(image_tar)
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
        check = workflow.split("- name: Check target Dockerfile", 1)[1].split("- name:", 1)[0]
        build = workflow.split("- name: Build and package native local demo", 1)[1].split("- name:", 1)[0]
        self.assertIn("ce-image --platform", check)
        self.assertIn('--build-arg "CE_IMAGE=$CE_IMAGE"', check)
        self.assertIn("portable_demo.py build", build)
        for platform in ("linux/amd64", "linux/arm64"):
            self.assertEqual(portable_demo.pins()[portable_demo.PLATFORM_CE_KEY[platform]].split("@", 1)[0], "3.5.0")
        prepare = workflow.split("- name: Capture portable package metadata", 1)[1].split("- name:", 1)[0]
        qualify = workflow.split("- name: Run local Compose and browser qualification", 1)[1].split("- name:", 1)[0]
        self.assertIn("$GITHUB_ENV", prepare)
        self.assertNotIn("compose_release_qualification.py", prepare)
        self.assertIn("compose_release_qualification.py", qualify)

    def test_valkey_runtime_loader_is_target_neutral_and_both_commands_are_executed(self) -> None:
        dockerfile = (ROOT / "Dockerfile.g7").read_text()
        self.assertIn('case "$TARGETARCH" in amd64) musl_arch=x86_64;; arm64) musl_arch=aarch64;;', dockerfile)
        self.assertIn("/tmp/volt-valkey-ld-musl.so.1", dockerfile)
        self.assertIn("/opt/valkey/lib/ld-musl.so.1", dockerfile)
        self.assertNotIn("/opt/valkey/lib/ld-musl-x86_64.so.1", dockerfile)
        self.assertIn("RUN valkey-server --version && valkey-cli --version", dockerfile)
        for wrapper in ("valkey-server", "valkey-cli"):
            contents = (ROOT / "docker/g7" / wrapper).read_text()
            self.assertIn("/opt/valkey/lib/ld-musl.so.1", contents)
            self.assertNotIn("x86_64", contents)

    def test_source_free_artifact_verifies_outside_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = self.package(root)
            extracted = root / "downloaded"
            extracted.mkdir()
            import archive
            archive.safe_extract(package, extracted)
            package_dir = extracted / f"volt-portable-demo-{portable_demo.VERSION}"
            result = subprocess.run([sys.executable, str(package_dir / "offline-tools/portable_demo.py"),
                "verify", "--archive", str(package)], cwd=extracted, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((package_dir / "installer.tar.gz").is_file())
            self.assertIn("--bootstrap-principal", (package_dir / "PORTABLE-INSTALL.md").read_text())

    def test_demo_image_missing_or_contradictory_compose_labels_is_rejected(self) -> None:
        for labels in (
            {"org.volt.oidc-deployment-modes": "demo"},
            {"org.volt.compose-install.contract": "0"},
            {"org.volt.compose.source-snapshot": "sha256:" + "0" * 64},
        ):
            with self.subTest(labels=labels), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                image_tar, revision, snapshot = make_image(root)
                with tarfile.open(image_tar) as source:
                    entries = {member.name: source.extractfile(member).read() for member in source.getmembers()
                               if member.isfile()}
                config_name = json.loads(entries["manifest.json"])[0]["Config"]
                config = json.loads(entries[config_name])
                for key, value in labels.items():
                    config["config"]["Labels"][key] = value
                config_bytes = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
                entries.pop(config_name)
                image_id = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
                entries[image_id.removeprefix("sha256:") + ".json"] = config_bytes
                entries["manifest.json"] = json.dumps([{"Config": image_id.removeprefix("sha256:") + ".json",
                    "RepoTags": ["volt-portable-demo:arm64"], "Layers": ["layer.tar"]}]).encode()
                with tarfile.open(image_tar, "w") as target:
                    for name, data in entries.items():
                        info = tarfile.TarInfo(name); info.size = len(data); target.addfile(info, io.BytesIO(data))
                with self.assertRaisesRegex(ValueError, "required Compose capability or source snapshot"):
                    archive_manifest = {"image_id": image_id, "platform": "linux/arm64",
                        "source_commit": revision, "version": portable_demo.VERSION}
                    portable_demo.archive.validate_docker_archive(image_tar, archive_manifest)

    def test_oci_portable_manifest_keeps_index_and_config_id_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); revision = "b" * 40
            source = root / "source.tar"
            with tarfile.open(source, "w") as tf:
                data = b"source\n"; info = tarfile.TarInfo("source.txt"); info.size = len(data); tf.addfile(info, io.BytesIO(data))
            snapshot = "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
            layer_io = io.BytesIO()
            with tarfile.open(fileobj=layer_io, mode="w"): pass
            layer = layer_io.getvalue()
            config = {"os":"linux", "architecture":"arm64", "config":{"Labels":{
                "org.opencontainers.image.revision":revision,"org.opencontainers.image.version":portable_demo.VERSION,
                "org.volt.oidc-deployment-modes":"demo,external","org.volt.compose-install.contract":"1",
                "org.volt.compose.source-snapshot":snapshot}},"rootfs":{"type":"layers","diff_ids":["sha256:"+hashlib.sha256(layer).hexdigest()]}}
            blobs = {}
            def descriptor(data, media):
                digest = hashlib.sha256(data).hexdigest(); blobs["blobs/sha256/"+digest] = data
                return {"mediaType":media,"digest":"sha256:"+digest,"size":len(data)}
            cfg = descriptor(json.dumps(config,sort_keys=True,separators=(",",":")).encode(),"application/vnd.oci.image.config.v1+json")
            lay = descriptor(layer,"application/vnd.oci.image.layer.v1.tar")
            image_manifest = descriptor(json.dumps({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
                "config":cfg,"layers":[lay]},sort_keys=True,separators=(",",":")).encode(),"application/vnd.oci.image.manifest.v1+json")
            index = {"schemaVersion":2,"manifests":[{**image_manifest,"platform":{"os":"linux","architecture":"arm64"},
                "annotations":{"io.containerd.image.name":"volt-portable-demo:arm64"}}]}
            compat = [{"Config":"blobs/sha256/"+cfg["digest"].split(":",1)[1],"Layers":["blobs/sha256/"+lay["digest"].split(":",1)[1]],"RepoTags":["volt-portable-demo:arm64"]}]
            image = root / "oci.tar"
            entries = {"oci-layout":b'{"imageLayoutVersion":"1.0.0"}',"index.json":json.dumps(index).encode(),
                "manifest.json":json.dumps(compat).encode(),**blobs}
            with tarfile.open(image,"w") as tf:
                for name,data in entries.items():
                    info=tarfile.TarInfo(name); info.size=len(data); tf.addfile(info,io.BytesIO(data))
            image_id = image_manifest["digest"]
            manifest = portable_demo._manifest_for_image(image, source, image_id, "linux/arm64", revision, snapshot,
                "volt-portable-demo:arm64")
            self.assertNotEqual(manifest["image_id"], manifest["image_config_id"])
            self.assertEqual(manifest["image_config_id"], cfg["digest"])

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
