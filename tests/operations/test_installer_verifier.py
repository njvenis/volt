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
from uvm.installer.verifier import verify_closed_bundle


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


class IndependentVerifierArchiveTests(unittest.TestCase):
    def test_default_docker_target_excludes_local_fixture_trust_material(self):
        dockerfile = (Path(__file__).parents[2] / "tools/release/verifier.Dockerfile").read_text()
        stages = [line.removeprefix("FROM ") for line in dockerfile.splitlines()
                  if line.startswith("FROM ")]
        self.assertEqual(stages[-1], "verifier-base AS verifier-production")
        fixture_stage = stages.index("verifier-base AS verifier-fixture")
        self.assertLess(fixture_stage, len(stages) - 1)

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
