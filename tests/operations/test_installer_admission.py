from __future__ import annotations

import base64
import hashlib
import json
import unittest

from uvm.installer.admission import PROVENANCE_TYPE, platform_children, verify_runtime


class RuntimeAdmissionTests(unittest.TestCase):
    def test_index_digest_and_exact_platform_children_are_required(self):
        index = {"schemaVersion": 2, "manifests": [
            {"digest": "sha256:" + "a" * 64, "platform": {"os": "linux", "architecture": "amd64"}},
            {"digest": "sha256:" + "b" * 64, "platform": {"os": "linux", "architecture": "arm64"}},
            {"digest": "sha256:" + "c" * 64, "platform": {"os": "unknown", "architecture": "unknown"}},
        ]}
        raw = json.dumps(index, separators=(",", ":")).encode()
        reference = "ghcr.io/njvenis/volt@sha256:" + hashlib.sha256(raw).hexdigest()
        self.assertEqual(platform_children(raw, reference), {
            "linux/amd64": "sha256:" + "a" * 64,
            "linux/arm64": "sha256:" + "b" * 64,
        })
        with self.assertRaisesRegex(ValueError, "do not match"):
            platform_children(raw + b"\n", reference)

    def test_authenticated_runtime_requires_bundle_and_provenance_to_bind_exact_source(self):
        index = {"schemaVersion": 2, "manifests": [
            {"digest": "sha256:" + "a" * 64, "platform": {"os": "linux", "architecture": "amd64"}},
            {"digest": "sha256:" + "b" * 64, "platform": {"os": "linux", "architecture": "arm64"}},
        ]}
        raw_index = json.dumps(index, separators=(",", ":")).encode()
        index_digest = hashlib.sha256(raw_index).hexdigest()
        reference = "ghcr.io/njvenis/volt@sha256:" + index_digest
        children = platform_children(raw_index, reference)
        predicate = {"schema_version": 1, "release_version": "0.1.0-rc.4",
            "source_repository": "https://github.com/njvenis/volt", "source_revision": "d" * 40,
            "source_snapshot": "sha256:" + "e" * 64, "image_index_digest": "sha256:" + index_digest,
            "platform_children": children, "installer_bundle_sha256": "f" * 64}
        statement = {"_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": reference, "digest": {"sha256": index_digest}}],
            "predicateType": PROVENANCE_TYPE, "predicate": predicate}
        verified = json.dumps([{"payload": base64.b64encode(json.dumps(statement).encode()).decode()}])
        image = [{"Id": "sha256:" + "1" * 64, "Os": "linux", "Architecture": "amd64",
            "Config": {"Labels": {"org.volt.compose.source-snapshot": predicate["source_snapshot"],
                "org.opencontainers.image.revision": predicate["source_revision"],
                "org.opencontainers.image.version": "0.1.0-rc.4",
                "org.volt.compose-install.contract": "1", "org.volt.oidc-deployment-modes": "demo,external,local"}}}]
        accepted = verify_runtime(image_output=json.dumps(image), index_data=raw_index,
            provenance_output=verified, reference=reference, source_revision="d" * 40,
            source_snapshot=predicate["source_snapshot"], version="0.1.0-rc.4",
            platform="linux/amd64", bundle_sha256="f" * 64)
        self.assertEqual(accepted["platform_children"], children)
        predicate["source_revision"] = "0" * 40
        statement["predicate"] = predicate
        rejected = json.dumps([{"payload": base64.b64encode(json.dumps(statement).encode()).decode()}])
        with self.assertRaisesRegex(ValueError, "provenance"):
            verify_runtime(image_output=json.dumps(image), index_data=raw_index,
                provenance_output=rejected, reference=reference, source_revision="d" * 40,
                source_snapshot="sha256:" + "e" * 64, version="0.1.0-rc.4",
                platform="linux/amd64", bundle_sha256="f" * 64)


if __name__ == "__main__":
    unittest.main()
