from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


class HelperPlatformTests(unittest.TestCase):
    def test_wrong_host_default_cannot_select_foreign_helper_child(self):
        spec = importlib.util.spec_from_file_location('compose_platform_setup', ROOT / 'deploy/compose/setup.py')
        setup = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(setup)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / 'executions.jsonl'
            docker = root / 'docker'
            docker.write_text(f'#!{sys.executable}\n' + '''import json,os,sys
from pathlib import Path
args=sys.argv[1:]
if args[0]=='run':
 platform=args[args.index('--platform')+1] if '--platform' in args else os.environ['DOCKER_DEFAULT_PLATFORM']
 with open(os.environ['PLATFORM_EXECUTION_LOG'],'a') as stream:stream.write(json.dumps({'selected_child':platform,'argv':args})+'\\n')
 if platform!='linux/amd64':sys.exit(86)
elif args[:2]==['container','inspect'] and '--format' not in args and len(args)==3:
 if os.environ.get('PROVISIONING')=='1':sys.exit(1)
 print('[{}]')
elif args[:2]==['volume','inspect']:
 if os.environ.get('PROVISIONING')=='1':sys.exit(1)
 print('[]')
elif args[:2]==['network','inspect']:sys.exit(1)
''')
            docker.chmod(0o700)
            environment = {**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'],
                'DOCKER_DEFAULT_PLATFORM': 'linux/arm64', 'PLATFORM_EXECUTION_LOG': str(log)}
            info = {'project': 'volt-platform-proof', 'owner_token': 'owned', 'platform': 'linux/amd64',
                'image': '127.0.0.1:46150/volt@sha256:' + 'a' * 64,
                'image_admission': {'id': 'sha256:' + 'b' * 64}, 'mode': 'local',
                'subnet': '10.240.0.0/28', 'gateway': '10.240.0.1',
                'backup_inventory': {'postgres': {'postgres_version': '18'}, 'media': {}, 'state': {}}}
            (root / 'instance.json').write_text(json.dumps(info))
            with patch.dict(os.environ, environment, clear=True):
                setup.admit_actual_local_container(root, info)
                setup.local_host_helper(root, info, 'prepare-start', '{}')
                with patch.dict(os.environ, {'PROVISIONING': '1'}), \
                        patch.object(setup, 'load_instance', return_value=(root, dict(info))), \
                        patch.object(setup, 'inspect_image', return_value=info['image_admission']), \
                        patch.object(setup, 'resolved_compose', return_value=([], root / '.env', environment)):
                    # This fake Docker records child selection but supplies no
                    # real FD owner/readiness. The new fixed protocol must stop
                    # there, rather than accepting an unrelated held lock.
                    with self.assertRaises(SystemExit):
                        setup.provision_restore(SimpleNamespace(directory=str(root)))
            launcher = (ROOT / 'deploy/compose/launcher.sh').read_text()
            body = launcher.split('helper() {', 1)[1].split('\n}', 1)[0]
            script = ('set -eu\nPLATFORM=linux/amd64\nPACKAGE=/signed-package\n'
                'CACHE_DIRECTORY=/verified-cache/originals\nCACHE_PARENT=/verified-cache\nWORK=/private-work\n'
                'IMAGE_REF=127.0.0.1:46150/volt@sha256:' + 'a' * 64 + '\nhelper() {' + body + '\n}\nhelper /private-state host-validate /state\n')
            result = subprocess.run(['sh', '-c', script], env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            executions = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(len(executions), 3)
            self.assertTrue(all(row['selected_child'] == 'linux/amd64' for row in executions))
            # A source/manual call without authenticated cache/receipt context
            # must stop before any offline FD owner or provision helper.
            self.assertFalse(any('--offline-restore-provision' in row['argv'] for row in executions))
            self.assertFalse(any('emit-request' in row['argv'] for row in executions))
            self.assertTrue(all('--pull=never' in row['argv'] for row in executions if '/package/setup.py' in row['argv']))
            self.assertFalse(any('advance-fence' in row['argv'] for row in executions))


if __name__ == '__main__':
    unittest.main()
