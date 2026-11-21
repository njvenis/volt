from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from uvm.installer.admission import RC4_FILES
from uvm.installer.verifier import verify_closed_bundle, verify_platform_configs


REFERENCE = "ghcr.io/njvenis/volt@sha256:" + "a" * 64


def make_bundle(path: Path, *, duplicate: bool = False) -> None:
    payload = {name: (b"0.1.0-rc.4\n" if name == "VERSION" else
        REFERENCE.encode() + b"\n" if name == "release-image.ref" else
        b"Pinned runtime " + REFERENCE.encode() if name == "README.md" else b"fixture")
        for name in RC4_FILES}
    manifest = {"format_version": 1, "bundle_version": "0.1.0-rc.4",
        "release_image": REFERENCE,
        "files": {name: hashlib.sha256(value).hexdigest() for name, value in payload.items()}}
    payload["manifest.json"] = (json.dumps(manifest, sort_keys=True) + "\n").encode()
    with path.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz, \
            tarfile.open(fileobj=gz, mode="w") as archive:
        for name, content in payload.items():
            item = tarfile.TarInfo(f"volt-compose-0.1.0-rc.4/{name}")
            item.size = len(content)
            item.mode = 0o600
            archive.addfile(item, io.BytesIO(content))
        if duplicate:
            item = tarfile.TarInfo("volt-compose-0.1.0-rc.4/VERSION")
            item.size = 3
            archive.addfile(item, io.BytesIO(b"bad"))


class PlatformConfigAdmissionTests(unittest.TestCase):
    def fixture(self, *, arm_source="a" * 40):
        records, descriptors, children = {}, [], {}
        for architecture in ("amd64", "arm64"):
            config = json.dumps({"os": "linux", "architecture": architecture, "config": {"Labels": {
                "org.opencontainers.image.revision": arm_source if architecture == "arm64" else "a" * 40,
                "org.volt.compose.source-snapshot": "sha256:" + "b" * 64,
                "org.opencontainers.image.version": "0.1.0-rc.4",
                "org.volt.compose-install.contract": "1", "org.volt.oidc-deployment-modes": "local"}}}).encode()
            config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
            manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"digest": config_digest, "size": len(config), "mediaType": "application/vnd.oci.image.config.v1+json"},
                "layers": [{"digest": "sha256:" + "c" * 64, "size": 5}]}).encode()
            digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
            records["manifests", digest] = manifest
            records["blobs", config_digest] = config
            descriptors.append({"digest": digest, "size": len(manifest),
                "mediaType": "application/vnd.oci.image.manifest.v1+json", "platform": {"os": "linux", "architecture": architecture}})
            children["linux/" + architecture] = digest
            if architecture == "amd64":
                image_id = config_digest
        index = {"schemaVersion": 2, "manifests": descriptors}
        runtime = {"image_id": image_id, "platform": "linux/amd64", "platform_children": children}
        return records, index, runtime

    def verify(self, records, index, runtime, image_output=None):
        return verify_platform_configs(runtime, reference="127.0.0.1:46150/volt@sha256:" + "d" * 64,
            source_revision="a" * 40, source_snapshot="sha256:" + "b" * 64, version="0.1.0-rc.4",
            index_data=json.dumps(index).encode(), fixture=True, image_output=image_output, fetch=lambda kind, digest: records[kind, digest])

    def test_both_actual_children_admit_and_selected_config_is_bound(self):
        records, index, runtime = self.fixture()
        admitted = self.verify(records, index, runtime)
        self.assertEqual(admitted["linux/amd64"], runtime["image_id"])
        self.assertEqual(set(admitted), {"linux/amd64", "linux/arm64"})
        with self.assertRaisesRegex(ValueError, "selected Docker config") :
            self.verify(records, index, {**runtime, "image_id": "sha256:" + "0" * 64})

    def test_docker29_descriptor_ids_require_the_exact_authenticated_manifest_or_index(self):
        records, index, runtime = self.fixture()
        index["mediaType"] = "application/vnd.oci.image.index.v1+json"
        child = index["manifests"][0]
        engine = {**runtime, "image_id": child["digest"]}
        inspected = json.dumps([{"Id": child["digest"], "Descriptor": child}])
        result = self.verify(records, index, engine, inspected)
        self.assertEqual(engine["image_config_id"], result["linux/amd64"])
        with self.assertRaisesRegex(ValueError, "descriptor ID"):
            self.verify(records, index, engine, json.dumps([{"Descriptor": {**child, "size": child["size"] + 1}}]))

    def test_mixed_source_other_platform_cannot_be_labelled_as_current(self):
        records, index, runtime = self.fixture(arm_source="e" * 40)
        with self.assertRaisesRegex(ValueError, "source/platform"):
            self.verify(records, index, runtime)

    def test_child_digest_size_and_media_are_checked_before_candidate_execution(self):
        for change in ("bytes", "size", "media"):
            records, index, runtime = self.fixture()
            if change == "bytes":
                key = ("manifests", runtime["platform_children"]["linux/amd64"])
                records[key] += b" "
            elif change == "size":
                index["manifests"][0]["size"] += 1
            else:
                index["manifests"][0]["mediaType"] = "application/vnd.oci.image.index.v1+json"
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify(records, index, runtime)


class IndependentVerifierArchiveTests(unittest.TestCase):
    def test_default_docker_target_excludes_local_fixture_trust_material(self):
        dockerfile = (Path(__file__).parents[2] / "tools/release/verifier.Dockerfile").read_text()
        stages = [line.removeprefix("FROM ") for line in dockerfile.splitlines()
                  if line.startswith("FROM ")]
        self.assertEqual(stages[-1], "verifier-base AS verifier-production")
        fixture_stage = stages.index("verifier-base AS verifier-fixture")
        self.assertLess(fixture_stage, len(stages) - 1)

    def test_only_baked_public_fixture_policy_is_readable_by_admitted_host_uid(self):
        dockerfile=(Path(__file__).parents[2]/'tools/release/verifier.Dockerfile').read_text()
        fixture=dockerfile.split('FROM verifier-base AS verifier-fixture\n',1)[1].split('FROM verifier-base AS verifier-production',1)[0]
        copies=[line for line in fixture.splitlines()if line.startswith('COPY ')]
        self.assertEqual(set(copies),{
            f'COPY --from=fixture-policy --chown=65532:65532 --chmod=0444 /{name} /usr/local/share/volt-verifier/{name}'
            for name in ('fixture-trust.json','fixture.pub','trusted-root.json')})
        self.assertEqual(len(copies),3)
        self.assertIn('RUN chmod 0755 /usr/local/share/volt-verifier',fixture)
        self.assertLess(fixture.rindex('COPY '),fixture.index('RUN chmod 0755'))
        self.assertNotIn('USER ',fixture)
        self.assertNotIn('chmod 0755',dockerfile.split('FROM verifier-base AS verifier-fixture',1)[0])
        self.assertNotIn('--chmod=0444',dockerfile.split('FROM verifier-base AS verifier-fixture',1)[0])
        self.assertTrue(dockerfile.rstrip().endswith('FROM verifier-base AS verifier-production'))

    def test_closed_signed_descriptor_inventory_and_exact_runtime_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "bundle.tar.gz"
            make_bundle(archive)
            result = verify_closed_bundle(archive, reference=REFERENCE)
            self.assertEqual(result["bundle_sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(result["bundle_version"], "0.1.0-rc.4")
            self.assertEqual(result["files"], len(RC4_FILES))
            with self.assertRaisesRegex(ValueError, "runtime reference mismatch"):
                verify_closed_bundle(archive, reference=REFERENCE[:-1] + "b")

    def test_duplicate_archive_member_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "bundle.tar.gz"
            make_bundle(archive, duplicate=True)
            with self.assertRaisesRegex(ValueError, "duplicate members"):
                verify_closed_bundle(archive, reference=REFERENCE)

    def test_archive_size_bound_is_checked_before_tar_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "bundle.tar.gz"
            archive.write_bytes(b"x" * (64 * 1024 * 1024 + 1))
            with self.assertRaisesRegex(ValueError, "archive size limit"):
                verify_closed_bundle(archive, reference=REFERENCE)


if __name__ == "__main__":
    unittest.main()
