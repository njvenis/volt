"""Full cached policy contracts; crypto transport is substituted ONLY here."""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tests.operations.test_installer_verifier import PlatformConfigAdmissionTests
from uvm.installer import offline_artifacts as offline, verifier
from uvm.installer.admission import RC4_FILES, platform_children


class OfflineGraphPolicyTests(unittest.TestCase):
    def fixture(self, root, *, arm_source='a' * 40, mismatched_launcher=False):
        directory = root / 'closure'; directory.mkdir(mode=0o700)
        records, index, selected = PlatformConfigAdmissionTests().fixture(arm_source=arm_source)
        index['mediaType'] = 'application/vnd.oci.image.index.v1+json'
        index_raw = offline.canonical(index); reference = '127.0.0.1:46150/volt@' + offline.digest(index_raw)
        verifier_raw = offline.canonical({'schemaVersion': 2, 'mediaType': index['mediaType'], 'manifests': []})
        verifier_reference = '127.0.0.1:46150/volt-installer-verifier@' + offline.digest(verifier_raw)
        files = {}
        def add(name, raw):
            path = directory / name; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            for parent in (path.parent, *path.parent.parents):
                if parent == directory.parent: break
                parent.chmod(0o700)
            path.write_bytes(raw); path.chmod(0o600)
            files[name] = {'bytes': len(raw), 'sha256': offline.digest(raw)}
        for layout in offline.LAYOUTS:
            if layout == 'verifier': raw = verifier_raw
            elif layout == 'runtime-index': raw = index_raw
            else: raw = records['manifests', selected['platform_children']['linux/' + layout.split('-')[1]]]
            add(layout + '/blobs/sha256/' + offline.digest(raw)[7:], raw)
            add(layout + '/index.json', offline.canonical({'schemaVersion': 2, 'manifests': [{
                'digest': offline.digest(raw), 'size': len(raw), 'mediaType': json.loads(raw)['mediaType']}]}))
            add(layout + '/oci-layout', b'{"imageLayoutVersion":"1.0.0"}')
            if layout != 'verifier':
                for (_kind, value), content in records.items():
                    add(layout + '/blobs/sha256/' + value[7:], content)
        launcher = ('original signed launcher ' + verifier_reference).encode()
        payload = {name: b'unit fixture' for name in RC4_FILES}
        payload.update({'VERSION': b'0.1.0-rc.4\n', 'release-image.ref': reference.encode(),
            'README.md': reference.encode(), 'launcher.sh': launcher + (b'other' if mismatched_launcher else b'')})
        manifest = {'format_version': 1, 'bundle_version': '0.1.0-rc.4', 'release_image': reference,
            'verifier_reference': verifier_reference,
            'files': {name: offline.digest(raw)[7:] for name, raw in payload.items()}}
        payload['manifest.json'] = offline.canonical(manifest)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            for name, raw in payload.items():
                info = tarfile.TarInfo('volt-compose-0.1.0-rc.4/' + name); info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
        for name, raw in {'launcher.sh': launcher, 'installer.bundle.tar.gz': buffer.getvalue(),
                'launcher.sigstore.json': b'original blob proof fixture',
                'installer.bundle.sigstore.json': b'original bundle proof fixture'}.items():
            add('package/' + name, raw)
        release = {'version': '0.1.0-rc.4', 'signer': 'independent-fixture', 'issuer': 'independent-fixture',
            'runtime_reference': reference, 'verifier_reference': verifier_reference,
            'source_revision': 'a' * 40, 'source_snapshot': 'sha256:' + 'b' * 64,
            'launcher_sha256': offline.digest(launcher), 'bundle_sha256': offline.digest(buffer.getvalue())}
        add('closure.json', offline.canonical({'schema_version': 1, 'profile': offline.PROFILE,
            'release': release, 'files': files.copy()}))
        policy = root / 'baked-policy.json'; policy.write_text('{}')
        engine = root / 'engine.json'; engine.write_text(json.dumps([{'Id': selected['image_id'],
            'Os': 'linux', 'Architecture': 'amd64',
            'Config': json.loads(records['blobs', selected['image_id']])['config']}]))
        actual_index = root / 'index.json'; actual_index.write_bytes(index_raw)
        args = argparse.Namespace(bundle=directory / 'package/installer.bundle.tar.gz',
            bundle_signature=directory / 'package/installer.bundle.sigstore.json',
            expected_verifier_reference=verifier_reference, reference=reference,
            source_revision='a' * 40, source_snapshot='sha256:' + 'b' * 64,
            version='0.1.0-rc.4', signer=release['signer'], issuer=release['issuer'],
            platform='linux/amd64', index=actual_index, image_inspect=engine)
        self.predicate = {'schema_version': 1, 'release_version': args.version,
            'source_repository': 'https://github.com/njvenis/volt', 'source_revision': args.source_revision,
            'source_snapshot': args.source_snapshot, 'image_index_digest': offline.digest(index_raw),
            'platform_children': platform_children(index_raw, reference),
            'installer_bundle_sha256': offline.digest(buffer.getvalue())[7:]}
        self.bad_child_subject = False
        self.references = {'runtime-index': reference, 'verifier': verifier_reference,
            **{'runtime-' + platform.split('/')[1]: reference.split('@')[0] + '@' + value
                for platform, value in self.predicate['platform_children'].items()}}
        return args, directory, policy

    def crypto(self, argv, **_kwargs):
        if argv[1] == 'verify-blob':
            return subprocess.CompletedProcess(argv, 0, '', '')
        predicate = argv[argv.index('--type') + 1]
        layout = Path(argv[argv.index('--local-image') + 1]).name
        subject = self.references[layout].split('@sha256:')[1]
        if self.bad_child_subject and layout == 'runtime-arm64': subject = '0' * 64
        statement = {'predicateType': predicate, 'subject': [{'digest': {'sha256': subject}}],
            'predicate': self.predicate if predicate == offline.RUNTIME_TYPE else {}}
        output = json.dumps({'payload': base64.b64encode(offline.canonical(statement)).decode()}, indent=3) + '\n\n'
        if predicate == offline.RUNTIME_TYPE: self.original_verified_envelope = output
        return subprocess.CompletedProcess(argv, 0, output, '')

    def test_complete_cached_graph_applies_real_policy_and_preserves_crypto_output_bytes(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            args, directory, policy = self.fixture(Path(temporary))
            stack.enter_context(patch.object(offline, 'ROOT', directory))
            stack.enter_context(patch.object(verifier, 'FIXTURE_POLICY', policy))
            crypto = stack.enter_context(patch.object(offline.subprocess, 'run', side_effect=self.crypto))
            observed = stack.enter_context(patch.object(verifier, 'verify_runtime', wraps=verifier.verify_runtime))
            stack.enter_context(patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('offline network forbidden')))
            result = verifier.verify_offline(args)
            self.assertEqual(result['runtime']['image_id_kind'], 'config')
            self.assertEqual(len(result['runtime']['platform_configs']), 2)
            self.assertEqual(observed.call_args.kwargs['provenance_output'], self.original_verified_envelope)
            self.assertEqual(crypto.call_count, 8)
            self.assertEqual(result['offline_artifacts']['profile'], 'volt_verified_installer_v1')
            self.assertEqual(result['offline_artifacts']['verifier_reference'], args.expected_verifier_reference)

    def test_other_platform_source_index_only_id_subject_and_bundle_drift_deny(self):
        for case in ('arm-source', 'index-id', 'subject', 'provenance-source', 'launcher', 'verifier-pin'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
                args, directory, policy = self.fixture(Path(temporary),
                    arm_source='e' * 40 if case == 'arm-source' else 'a' * 40, mismatched_launcher=case == 'launcher')
                if case == 'index-id':
                    rows = json.loads(args.image_inspect.read_text()); rows[0]['Id'] = args.reference.split('@')[1]
                    args.image_inspect.write_text(json.dumps(rows))
                elif case == 'subject': self.bad_child_subject = True
                elif case == 'provenance-source': self.predicate['source_revision'] = '0' * 40
                elif case == 'verifier-pin':
                    args.expected_verifier_reference = args.expected_verifier_reference.split('@')[0] + '@sha256:' + '0' * 64
                stack.enter_context(patch.object(offline, 'ROOT', directory))
                stack.enter_context(patch.object(verifier, 'FIXTURE_POLICY', policy))
                stack.enter_context(patch.object(offline.subprocess, 'run', side_effect=self.crypto))
                with self.assertRaises(ValueError): verifier.verify_offline(args)
