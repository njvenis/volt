"""Guard the maintained real-kernel component, not a product TLS interface."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from tools.compose_release_qualification import qualify_route_process_visibility, _validate_route_visibility_tmpfs


class RouteProcessComponentTests(unittest.TestCase):
    def test_remote_endpoint_denies_without_any_client_or_daemon_call(self):
        with tempfile.TemporaryDirectory() as root, patch.dict('os.environ',
                {'DOCKER_HOST': 'blocked-nonnetwork-context://sentinel'}), \
                patch('tools.compose_release_qualification.run') as run:
            with self.assertRaisesRegex(RuntimeError, 'local Unix daemon'):
                qualify_route_process_visibility(admission={}, selected={}, evidence=Path(root))
            run.assert_not_called()

    def test_changed_source_image_is_denied_before_container_creation(self):
        admission = {'image_reference': '127.0.0.1:46150/volt@sha256:' + 'a'*64,
            'platform': 'linux/amd64', 'image_id': 'sha256:' + 'b'*64,
            'image_config_id': 'sha256:' + 'c'*64, 'source_commit': 'd'*40,
            'source_snapshot': 'sha256:' + 'e'*64}
        image = {'Id': admission['image_config_id'], 'Descriptor': {}, 'Os': 'linux',
            'Architecture': 'amd64', 'Config': {'Labels': {
                'org.opencontainers.image.revision': 'f'*40,
                'org.volt.compose.source-snapshot': admission['source_snapshot']}}}
        def run(name, argv, evidence, **kwargs):
            self.assertNotIn('create', argv)
            return subprocess.CompletedProcess(argv, 0, 'same-server' if 'info' in argv else json.dumps([image]), '')
        with tempfile.TemporaryDirectory() as root, patch.dict('os.environ', {'DOCKER_HOST':'unix:///fixed-local'}), \
                patch('tools.compose_release_qualification.run', side_effect=run):
            with self.assertRaisesRegex(RuntimeError, 'source/platform mismatch'):
                qualify_route_process_visibility(admission=admission, selected={}, evidence=Path(root))


class ActualTmpfsRepresentationTests(unittest.TestCase):
    def test_empty_mounts_requires_exact_declared_masks_and_no_unexpected_mount(self):
        value = {'mounts': [], 'tmpfs': {'/tmp':'rw,noexec,nosuid,size=8m',
            '/app/media':'rw,noexec,nosuid,nodev,size=1m',
            '/opt/uvm/state':'rw,noexec,nosuid,nodev,size=1m',
            '/var/lib/postgresql/data':'rw,noexec,nosuid,nodev,size=1m'}}
        _validate_route_visibility_tmpfs(value)
        altered = copy.deepcopy(value);altered['tmpfs'].pop('/app/media')
        with self.assertRaises(RuntimeError):_validate_route_visibility_tmpfs(altered)
        altered = copy.deepcopy(value);altered['tmpfs']['/app/media']='rw,size=1m'
        with self.assertRaises(RuntimeError):_validate_route_visibility_tmpfs(altered)
        altered = copy.deepcopy(value);altered['mounts']=[{'Type':'volume','Destination':'/app/media'}]
        with self.assertRaises(RuntimeError):_validate_route_visibility_tmpfs(altered)
        altered = copy.deepcopy(value);altered['mounts']=[{'Type':'tmpfs','Destination':'/tmp'}]*2
        with self.assertRaises(RuntimeError):_validate_route_visibility_tmpfs(altered)
