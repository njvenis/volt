from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.compose_release_qualification import matching_publication_commit, qualify_backup_owner_loss


class OwnerLossControllerTests(unittest.TestCase):
    def test_directory_visibility_or_another_commit_is_not_durable_operation_evidence(self):
        expected = {'offline_publication_committed': 'capture', 'operation_id': 'exact-operation',
            'identity_sha256': 'sha256:' + 'a' * 64, 'completion_sha256': 'sha256:' + 'b' * 64}
        self.assertFalse(matching_publication_commit('directory now visible\nlocked=1\n', expected))
        self.assertTrue(matching_publication_commit('locked=1\n' + json.dumps(expected), expected))
        for field in expected:
            changed = {**expected, field: 'another-value'}
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'conflicts'):
                matching_publication_commit(json.dumps(changed), expected)
        with self.assertRaisesRegex(RuntimeError, 'repeated'):
            matching_publication_commit(json.dumps(expected) + '\n' + json.dumps(expected), expected)

    def test_foreign_caller_process_group_is_never_killed_or_removed(self):
        # Controller-only safety regression: fake Docker inspection points at
        # this test's group, distinct from the real disposable public child.
        # No Docker daemon or product authority is involved.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, backups, evidence = (root / name for name in ('state', 'backups', 'evidence'))
            for path in (state, backups, evidence):
                path.mkdir(mode=0o700)
            (state / 'instance.json').write_text(json.dumps({'project': 'owned', 'owner_token': 'owned-token'}))
            setup = root / 'public-child.py'; setup.write_text('import time\ntime.sleep(120)\n')
            docker = root / 'docker'
            docker.write_text(f'#!{sys.executable}\n' + '''import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with Path(os.environ['DOCKER_CALLS']).open('a') as output:output.write(json.dumps(args)+'\\n')
if args[0]=='ps':print('unrelated-owner')
elif args[0]=='inspect':print(json.dumps({'name':'/volt-offline-owned-'+os.environ['FOREIGN_PID'],'mounts':[]}))
else:raise SystemExit('unexpected mutation')
''')
            docker.chmod(0o700)
            environment = {**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'],
                'DOCKER_CALLS': str(root / 'calls.jsonl'), 'FOREIGN_PID': str(os.getpid())}
            with patch.dict(os.environ, environment):
                with self.assertRaisesRegex(RuntimeError, 'not created by this public caller'):
                    qualify_backup_owner_loss(setup=setup, launcher=None, launcher_env=environment,
                        state=state, backup_parent=backups, evidence=evidence)
            calls = [json.loads(line) for line in (root / 'calls.jsonl').read_text().splitlines()]
            self.assertEqual([row[0] for row in calls], ['ps', 'inspect'])
            self.assertEqual((evidence / 'backup-owner-loss-before.exit').read_text(), '-9\n')
            self.assertEqual(list(backups.iterdir()), [])
