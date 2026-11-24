from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.compose_release_qualification import qualify_admission_negatives

SEMANTIC = 'verifier.py: error: selected runtime platform differs from the admitted engine platform'


class AdmissionNegativeTargetTests(unittest.TestCase):
    def exercise(self, platform_exit=2, platform_error=SEMANTIC, *, unbound_bundle=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle, image, index = (root / name for name in ('bundle.tar.gz', 'image.json', 'index.json'))
            bundle.write_bytes(b'original authenticated bundle fixture')
            image.write_text(json.dumps([{'Id': 'sha256:' + 'a' * 64}]))
            index.write_text(json.dumps({'manifests': [{'digest': 'sha256:' + 'b' * 64}]}))
            bound_bundle = root / 'different-bundle.tar.gz' if unbound_bundle else bundle
            command = ['docker', 'run', '--platform', 'linux/amd64',
                '--mount', f'type=bind,src={bound_bundle},dst=/bundle.tar.gz,readonly',
                '--mount', f'type=bind,src={image},dst=/image.json,readonly',
                '--mount', f'type=bind,src={index},dst=/index.json,readonly', 'pinned-verifier',
                '--bundle', '/bundle.tar.gz', '--source-revision', 'c' * 40,
                '--source-snapshot', 'sha256:' + 'd' * 64, '--version', '0.1.0-rc.4',
                '--platform', 'linux/amd64']
            calls = {}

            def run(name, argv, *_args, **_kwargs):
                calls[name] = argv
                return subprocess.CompletedProcess(argv,
                    platform_exit if name == 'admission-negative-platform' else 2,
                    '', platform_error if name == 'admission-negative-platform' else 'verifier.py: error: rejected')

            with patch('tools.compose_release_qualification.run', side_effect=run):
                qualify_admission_negatives(command, bundle, image, index, root)
            return command, calls, json.loads((root / 'admission-negatives.json').read_text())

    def test_wrong_verifier_platform_still_executes_native_verifier(self):
        command, calls, result = self.exercise()
        actual = calls['admission-negative-platform']
        self.assertEqual(actual[:actual.index('pinned-verifier') + 1], command[:command.index('pinned-verifier') + 1])
        self.assertEqual(actual[actual.index('--platform') + 1], 'linux/amd64')
        self.assertEqual(actual[-2:], ['--platform', 'linux/arm64'])
        self.assertEqual(len(result['cases']), 7)
        self.assertEqual(result['status'], 'passed')

    def test_engine_platform_rejection_cannot_count_as_verifier_rejection(self):
        with self.assertRaisesRegex(RuntimeError, 'semantic platform rejection'):
            self.exercise(125, 'docker: no matching manifest for linux/arm64')

    def test_unrelated_verifier_failure_cannot_count_as_platform_rejection(self):
        with self.assertRaisesRegex(RuntimeError, 'semantic platform rejection'):
            self.exercise(2, 'verifier.py: error: missing signature')

    def test_verifier_acceptance_fails_negative(self):
        with self.assertRaisesRegex(RuntimeError, 'accepted negative platform'):
            self.exercise(0, '')

    def test_unbound_negative_input_fails_before_verifier_execution(self):
        with self.assertRaisesRegex(RuntimeError, 'exactly one admitted bind mount: bundle.tar.gz'):
            self.exercise(unbound_bundle=True)
