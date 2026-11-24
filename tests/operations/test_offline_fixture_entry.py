from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.compose_release_qualification import qualify_offline_fixture_entry

VERIFIER = '127.0.0.1:46150/volt-installer-verifier@sha256:' + 'a' * 64


class OfflineFixtureEntryTests(unittest.TestCase):
    def exercise(self, failed_stage=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, evidence, fixture, closure = (root / name for name in ('private', 'evidence', 'fixture', 'closure'))
            for path in (private, evidence, fixture, closure):
                path.mkdir(mode=0o700)
            for name in ('fixture.pub', 'trusted-root.json'):
                (fixture / name).write_text('independent-test-material')
            calls = []

            def environment(*_args, **_kwargs):
                (private / 'minimal-host-tools.json').write_text('{}')
                return {'PATH': '/restricted-host-path'}

            def run(name, argv, *_args, **kwargs):
                calls.append((name, argv, kwargs))
                if name == failed_stage:
                    raise RuntimeError('cryptographic verification failed')
                return subprocess.CompletedProcess(argv, 0, '', '')

            with patch('tools.compose_release_qualification.launcher_minimal_environment', side_effect=environment), patch(
                    'tools.compose_release_qualification.run', side_effect=run):
                try:
                    qualify_offline_fixture_entry(closure=closure, fixture=fixture, verifier_reference=VERIFIER,
                        platform='linux/amd64', private=private, evidence=evidence)
                except RuntimeError:
                    self.assertIsNotNone(failed_stage)
            policies = {p.name: p.read_text() for p in (private / 'offline-entry-policies').iterdir()}
            result = json.loads((evidence / 'offline-first-entry.json').read_text()) if (evidence / 'offline-first-entry.json').exists() else None
            return calls, policies, result

    def test_exact_verifier_authenticated_before_its_first_execution(self):
        calls, policies, result = self.exercise()
        self.assertEqual(len(calls), 5)
        self.assertEqual(calls[-1][0], 'offline-first-entry-authenticated-verifier-execution')
        self.assertEqual(calls[-1][1][-2:], [VERIFIER, '--help'])
        self.assertIn('a' * 64, policies['signature.cue'])
        self.assertIn('subject: [{digest:', policies['signature.cue'])
        for _name, argv, kwargs in calls:
            self.assertIn('--pull=never', argv)
            self.assertEqual(argv[argv.index('--network') + 1], 'none')
            self.assertEqual(kwargs['env']['PATH'], '/restricted-host-path')
        self.assertIs(result['offline_lifecycle_qualified'], False)
        self.assertIs(result['candidate_application_executed'], False)

    def test_each_failed_authentication_blocks_verifier_execution(self):
        for stage in ('offline-first-entry-verifier-signature', 'offline-first-entry-verifier-slsa',
                      'offline-first-entry-launcher-sh', 'offline-first-entry-installer-bundle-tar-gz'):
            with self.subTest(stage=stage):
                calls, _policies, result = self.exercise(stage)
                self.assertNotIn('offline-first-entry-authenticated-verifier-execution', [name for name, *_rest in calls])
                self.assertIsNone(result)

    def test_candidate_cannot_choose_verifier_or_trust_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError):
                qualify_offline_fixture_entry(closure=root, fixture=root,
                    verifier_reference=VERIFIER, platform='linux/amd64', private=root, evidence=root)
            with self.assertRaises(ValueError):
                qualify_offline_fixture_entry(closure=root, fixture=root.parent,
                    verifier_reference='untrusted.example/verifier:latest', platform='linux/amd64', private=root, evidence=root)
