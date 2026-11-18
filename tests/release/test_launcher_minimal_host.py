from __future__ import annotations

import json
import io
import os
from pathlib import Path
import subprocess
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools.compose_release_qualification import docker_credential_helper_selection, launcher_minimal_environment


class MinimalHostDependencyTests(unittest.TestCase):
    def test_real_tar_gzip_archive_works_under_restricted_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); config = root / 'docker-config'; config.mkdir()
            archive = root / 'package.tar.gz'
            with tarfile.open(archive, 'w:gz') as output:
                item = tarfile.TarInfo('volt-compose-0.1.0-rc.4/VERSION'); item.size = 5
                output.addfile(item, io.BytesIO(b'rc.4\n'))
            docker = root / 'docker-stub'; docker.write_text('#!/bin/sh\nexit 0\n'); docker.chmod(0o700)
            original_which = shutil.which
            def which(name):
                return str(docker) if name == 'docker' else original_which(name)
            with patch.dict(os.environ, {'DOCKER_CONFIG': str(config)}), patch('shutil.which', side_effect=which):
                environment = launcher_minimal_environment(root / 'minimal')
            result = subprocess.run(['tar', '-tzf', str(archive)], env=environment,
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'volt-compose-0.1.0-rc.4/VERSION')

    def fixture(self, root):
        config = root / 'docker-config'; config.mkdir()
        (config / 'config.json').write_text(json.dumps({'credsStore': 'selected',
            'credHelpers': {'unused.example': '../../python3'}, 'auths': {'private.example': {'auth': 'DO_NOT_RECORD'}}}))
        binaries = root / 'trusted-bin'; binaries.mkdir()
        def which(name):
            path = binaries / name
            if not path.exists():
                path.write_text('#!/bin/sh\nprintf dependency-selected\\n\n'); path.chmod(0o700)
            return str(path)
        return config, which

    def test_only_required_configured_helper_works_and_reconstruction_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); config, which = self.fixture(root)
            destination = root / 'minimal'
            with patch.dict(os.environ, {'DOCKER_CONFIG': str(config)}), patch('shutil.which', side_effect=which):
                first = launcher_minimal_environment(destination, registries=('127.0.0.1:46150',))
                second = launcher_minimal_environment(destination, registries=('127.0.0.1:46150',))
            self.assertEqual(first, second)
            execution = subprocess.run(['/bin/sh', '-c', 'docker-credential-selected'], env=first,
                                       text=True, capture_output=True, timeout=5)
            self.assertEqual(execution.returncode, 0, execution.stderr)
            self.assertIn('dependency-selected', execution.stdout)
            self.assertFalse((destination / 'python3').exists())
            self.assertFalse((destination / 'node').exists())
            record = (root / 'minimal-host-tools.json').read_text()
            self.assertNotIn('DO_NOT_RECORD', record)
            self.assertNotIn('private.example', record)
            selected = json.loads(record)['credential_helper_selection']['selections']
            self.assertEqual(selected, [{'registry': '127.0.0.1:46150', 'config_field': 'credsStore',
                                         'executable': 'docker-credential-selected'}])

    def test_contradictory_existing_executable_is_rejected_without_overwriting_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); config, which = self.fixture(root); destination = root / 'minimal'
            with patch.dict(os.environ, {'DOCKER_CONFIG': str(config)}), patch('shutil.which', side_effect=which):
                launcher_minimal_environment(destination, registries=('127.0.0.1:46150',))
                link = destination / 'docker'; link.unlink(); link.write_text('keep contradictory file'); link.chmod(0o700)
                with self.assertRaisesRegex(RuntimeError, 'contradicts'):
                    launcher_minimal_environment(destination, registries=('127.0.0.1:46150',))
                self.assertEqual(link.read_text(), 'keep contradictory file')

    def test_needed_registry_helper_names_and_special_config_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); config = root / 'docker-config'; config.mkdir(); path = config / 'config.json'
            with patch.dict(os.environ, {'DOCKER_CONFIG': str(config)}):
                path.write_text(json.dumps({'credHelpers': {'127.0.0.1:46150': '../../python3'}}))
                with self.assertRaises(RuntimeError):
                    docker_credential_helper_selection(('127.0.0.1:46150',))
                path.unlink(); os.mkfifo(path, 0o600)
                with self.assertRaises(RuntimeError):
                    docker_credential_helper_selection(('127.0.0.1:46150',))
                path.unlink(); path.symlink_to('/dev/null')
                with self.assertRaises(RuntimeError):
                    docker_credential_helper_selection(('127.0.0.1:46150',))


if __name__ == '__main__':
    unittest.main()
