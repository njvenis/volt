from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from uvm.installer import offline_artifacts as offline


class OfflineArtifactTests(unittest.TestCase):
    def fixture(self, root, *, arm_variant=None):
        root.chmod(0o700)
        files = {}

        def add(name, raw):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            for directory in (path.parent, *path.parent.parents):
                if directory == root.parent:
                    break
                directory.chmod(0o700)
            path.write_bytes(raw); path.chmod(0o600)
            files[name] = {'bytes': len(raw), 'sha256': offline.digest(raw)}

        media = 'application/vnd.oci.image.manifest.v1+json'
        index_media = 'application/vnd.oci.image.index.v1+json'
        children = {}
        for arch in ('amd64', 'arm64'):
            raw = offline.canonical({'schemaVersion': 2, 'mediaType': media, 'architecture': arch})
            children[arch] = {'mediaType': media, 'digest': offline.digest(raw), 'size': len(raw),
                'platform': {'os': 'linux', 'architecture': arch}}
            if arch=='arm64'and arm_variant is not None:children[arch]['platform']['variant']=arm_variant
            add('runtime-' + arch + '/blobs/sha256/' + offline.digest(raw)[7:], raw)
            add('runtime-index/blobs/sha256/' + offline.digest(raw)[7:], raw)
        index_raw = offline.canonical({'schemaVersion': 2, 'mediaType': index_media,
            'manifests': list(children.values())})
        runtime_digest = offline.digest(index_raw)
        verifier_raw = offline.canonical({'schemaVersion': 2, 'mediaType': index_media, 'manifests': []})
        verifier_digest = offline.digest(verifier_raw)
        for name in offline.LAYOUTS:
            if name == 'runtime-index':
                raw, digest = index_raw, runtime_digest
            elif name == 'verifier':
                raw, digest = verifier_raw, verifier_digest
            else:
                digest = children[name.split('-')[1]]['digest']
                raw = (root / ('runtime-index/blobs/sha256/' + digest[7:])).read_bytes()
            add(name + '/blobs/sha256/' + digest[7:], raw)
            add(name + '/index.json', offline.canonical({'schemaVersion': 2, 'manifests': [{
                'mediaType': index_media if name in ('verifier', 'runtime-index') else media,
                'digest': digest, 'size': len(raw)}]}))
            add(name + '/oci-layout', b'{"imageLayoutVersion":"1.0.0"}')
        for name in offline.PACKAGE:
            add('package/' + name, ('fixture-' + name).encode())
        release = {'version': '0.1.0-rc.4', 'signer': 'fixture', 'issuer': 'fixture',
            'runtime_reference': '127.0.0.1:46150/volt@' + runtime_digest,
            'verifier_reference': '127.0.0.1:46150/volt-installer-verifier@' + verifier_digest,
            'source_revision': 'a' * 40, 'source_snapshot': 'sha256:' + 'b' * 64,
            'launcher_sha256': files['package/launcher.sh']['sha256'],
            'bundle_sha256': files['package/installer.bundle.tar.gz']['sha256']}
        document = {'schema_version': 1, 'profile': offline.PROFILE, 'release': release, 'files': files}
        (root / 'closure.json').write_bytes(offline.canonical(document))
        (root / 'closure.json').chmod(0o600)
        return document

    def test_arm_v8_layout_joins_same_original_child_without_other_variant_allowances(self):
        # Unsigned structural fixture only; no synthetic cryptographic claim.
        for variant in ('v8','v7',True,'V8'):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory()as tmp,patch.object(offline,'ROOT',Path(tmp)):
                root=Path(tmp);self.fixture(root,arm_variant=variant)
                if variant=='v8':
                    closure=offline.Closure(fixture=True);self.assertIn('runtime-arm64',closure.references.values())
                else:
                    with self.assertRaisesRegex(ValueError,'exact native child'):offline.Closure(fixture=True)

    def test_original_inventory_and_both_native_roots_are_required(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(offline, 'ROOT', Path(tmp)):
            root = Path(tmp); document = self.fixture(root)
            closure = offline.Closure(fixture=True)
            self.assertEqual(set(closure.references.values()), set(offline.LAYOUTS))
            (root / 'package/launcher.sh').write_bytes(b'mutated')
            with self.assertRaisesRegex(ValueError, 'changed during verification'):
                closure.assert_unchanged()
            with self.assertRaisesRegex(ValueError, 'hash/size'):
                offline.Closure(fixture=True)

    def test_unknown_files_directories_links_and_fifo_are_denied(self):
        for kind in ('file', 'directory', 'symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp, patch.object(offline, 'ROOT', Path(tmp)):
                root = Path(tmp); self.fixture(root)
                if kind == 'file':
                    (root / 'extra').write_text('extra')
                elif kind == 'directory':
                    (root / 'extra').mkdir(mode=0o700)
                else:
                    path = root / 'package/launcher.sh'; path.unlink()
                    if kind == 'symlink':
                        path.symlink_to(root / 'package/installer.bundle.tar.gz')
                    elif kind == 'hardlink':
                        path.hardlink_to(root / 'package/installer.bundle.tar.gz')
                    else:
                        os.mkfifo(path, 0o600)
                with self.assertRaises((ValueError, OSError)):
                    offline.Closure(fixture=True)

    def test_bind_only_exact_payload_from_successful_crypto_execution(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(offline, 'ROOT', Path(tmp)):
            root = Path(tmp); document = self.fixture(root); closure = offline.Closure(fixture=True)
            reference = document['release']['runtime_reference']
            statement = {'predicateType': offline.SIGNATURE_TYPE,
                'subject': [{'digest': {'sha256': reference.split('@sha256:')[1]}}]}
            envelope = {'payload': base64.b64encode(offline.canonical(statement)).decode()}
            with patch.object(offline.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(envelope), '')) as run:
                self.assertEqual(closure.verify_statement(reference, offline.SIGNATURE_TYPE,
                    signer='fixture', issuer='fixture'), statement)
                self.assertIn('--local-image', run.call_args.args[0])
                self.assertIn(offline.SIGNATURE_TYPE, run.call_args.args[0])
            for kind in ('wrong-subject', 'wrong-type', 'unverified'):
                altered = json.loads(json.dumps(statement))
                if kind == 'wrong-subject':
                    altered['subject'][0]['digest']['sha256'] = '0' * 64
                elif kind == 'wrong-type':
                    altered['predicateType'] = offline.RUNTIME_TYPE
                output = json.dumps({'payload': base64.b64encode(offline.canonical(altered)).decode()})
                with patch.object(offline.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1 if kind == 'unverified' else 0, output, 'failed')):
                    with self.assertRaises(ValueError):
                        closure.verify_statement(reference, offline.SIGNATURE_TYPE, signer='fixture', issuer='fixture')

    def test_production_cannot_learn_fixture_trust_from_cache(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(offline, 'ROOT', Path(tmp)):
            root = Path(tmp); self.fixture(root)
            with self.assertRaisesRegex(ValueError, 'release declaration'):
                offline.Closure(fixture=False)
