"""Typed export graph contracts, without signing or live registry authority."""
from __future__ import annotations

import unittest

from uvm.installer import offline_export as export
from uvm.installer.offline_artifacts import canonical, digest


class ExportGraphTests(unittest.TestCase):
    def test_no_candidate_repository_or_production_trust_fallback(self):
        for reference in ('https://another.invalid/volt@sha256:' + 'a' * 64,
                '127.0.0.1:46150/another@sha256:' + 'a' * 64):
            with self.assertRaises(ValueError): export.FixtureRegistry(reference)
        with self.assertRaisesRegex(ValueError, 'not independently provisioned'):
            export.export_originals(None, fixture=False)

    def fixture(self, *, layer_type=None, wrong_subject=False, native_proof_config=False):
        config = canonical({'os': 'linux', 'architecture': 'amd64', 'config': {}})
        proof = canonical({'mediaType': 'synthetic-proof-contract', 'verificationMaterial': {}, 'dsseEnvelope': {}})
        empty = b'{}'
        descriptor = lambda raw, media: {'digest': digest(raw), 'size': len(raw), 'mediaType': media}
        config_descriptor = descriptor(config, 'application/vnd.oci.image.config.v1+json')
        shared = descriptor(proof, 'application/vnd.oci.image.layer.v1.tar+gzip')
        filesystem = {'digest': 'sha256:' + 'c' * 64, 'size': 900 * 1024**2,
            'mediaType': layer_type or 'application/vnd.oci.image.layer.v1.tar+gzip'}
        manifest_type = 'application/vnd.oci.image.manifest.v1+json'
        root = canonical({'schemaVersion': 2, 'mediaType': manifest_type,
            'config': config_descriptor, 'layers': [shared, filesystem]})
        root_descriptor = descriptor(root, manifest_type)
        attachment = canonical({'schemaVersion': 2, 'mediaType': manifest_type,
            'artifactType': 'application/vnd.dev.sigstore.bundle.v0.3+json',
            'subject': {**root_descriptor, 'size': len(root) + (1 if wrong_subject else 0)},
            'config': config_descriptor if native_proof_config else descriptor(empty, export.EMPTY_CONFIG),
            'layers': [descriptor(proof, 'application/vnd.oci.image.layer.v1.tar+gzip'
                if native_proof_config else 'application/vnd.dev.sigstore.bundle.v0.3+json')]})
        refs = canonical({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json',
            'manifests': [descriptor(attachment, manifest_type)]})
        objects = {('manifests', digest(root)): root, ('blobs', digest(config)): config,
            ('manifests', digest(attachment)): attachment, ('blobs', digest(empty)): empty,
            ('blobs', digest(proof)): proof, ('manifests', 'sha256-' + digest(root)[7:]): refs}
        calls = []
        class Registry:
            def read(self, category, value, *, optional_404=False):
                calls.append((category, value))
                if category == 'referrers':
                    if not optional_404: raise AssertionError('only discovery permits missing endpoint')
                    return None
                if (category, value) not in objects:
                    raise ValueError('mandatory fetch failure')
                return objects[category, value]
        layout = export.MetadataLayout(Registry(), '127.0.0.1:46150/volt@' + digest(root))
        return layout, objects, calls, digest(proof), digest(config), filesystem['digest']

    def test_only_typed_filesystem_edges_omit_and_shared_proof_blob_survives(self):
        layout, _objects, calls, proof, _config, filesystem = self.fixture()
        result = layout.collect()
        self.assertEqual(result['manifests'][0]['digest'], layout.reference.split('@')[1])
        self.assertIn(proof, layout.blobs)
        self.assertNotIn(proof, layout.omitted_filesystem)
        self.assertEqual(layout.omitted_filesystem, {filesystem})
        self.assertNotIn(('blobs', filesystem), calls)
        self.assertIn(('manifests', 'sha256-' + layout.reference.split('@sha256:')[1]), calls)

    def test_native_config_and_filesystem_media_never_omit_a_referrer_proof_layer(self):
        # The same bytes first appear as an executable filesystem edge, then
        # as a proof/referrer layer with native OS/arch config and FS media.
        # The old config-only classification silently omitted BOTH edges.
        layout, _objects, calls, proof, _config, filesystem = self.fixture(native_proof_config=True)
        layout.collect()
        self.assertIn(('blobs', proof), calls)
        self.assertIn(proof, layout.blobs)
        self.assertNotIn(proof, layout.omitted_filesystem)
        self.assertEqual(layout.omitted_filesystem, {filesystem})

    def test_missing_proof_or_config_is_never_reclassified_as_omitted_filesystem(self):
        for missing in ('proof', 'config'):
            with self.subTest(missing=missing):
                layout, objects, _calls, proof, config, _filesystem = self.fixture()
                del objects['blobs', proof if missing == 'proof' else config]
                with self.assertRaisesRegex(ValueError, 'mandatory fetch failure'):
                    layout.collect()

    def test_unknown_layer_and_wrong_attachment_subject_fail_closed(self):
        for case in ('unknown-layer', 'wrong-subject'):
            with self.subTest(case=case):
                layout, *_unused = self.fixture(layer_type='application/octet-stream' if case == 'unknown-layer' else None,
                    wrong_subject=case == 'wrong-subject')
                with self.assertRaises(ValueError): layout.collect()
