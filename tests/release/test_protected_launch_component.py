"""No-state fresh-image component must not run a wrong image or remote daemon."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from tools.compose_release_qualification import qualify_protected_launch_component


class ProtectedLaunchComponentGuards(unittest.TestCase):
    def test_unregistered_image_never_contacts_docker(self):
        with tempfile.TemporaryDirectory()as root,patch('tools.compose_release_qualification.run')as run:
            with self.assertRaises(RuntimeError):qualify_protected_launch_component(image='untrusted:latest',
                image_digest='sha256:'+'f'*64,source_revision='a'*40,source_snapshot='sha256:'+'b'*64,component=Path(root)/'driver.py',evidence=Path(root))
            run.assert_not_called()
    def test_remote_context_never_contacts_daemon(self):
        with tempfile.TemporaryDirectory()as root,patch.dict('os.environ',{'DOCKER_HOST':'blocked-nonnetwork-context://sentinel'}),patch('tools.compose_release_qualification.run')as run:
            with self.assertRaises(RuntimeError):qualify_protected_launch_component(image='volt-easy-delivery-route-component:'+'a'*12,
                image_digest='sha256:'+'f'*64,source_revision='a'*40,source_snapshot='sha256:'+'b'*64,component=Path(root)/'driver.py',evidence=Path(root))
            run.assert_not_called()
    def test_wrong_source_image_denies_before_create(self):
        def run(name,argv,evidence,**kwargs):
            self.assertNotIn('create',argv)
            return subprocess.CompletedProcess(argv,0,'server-id'if'info'in argv else json.dumps([
                {'Id':'sha256:'+'a'*64,'Os':'linux','Architecture':'amd64','Config':{'Labels':{}}}]),'')
        with tempfile.TemporaryDirectory()as root,patch.dict('os.environ',{'DOCKER_HOST':'unix:///fixed'}),patch('tools.compose_release_qualification.run',side_effect=run):
            with self.assertRaisesRegex(RuntimeError,'source differs'):qualify_protected_launch_component(image='volt-easy-delivery-route-component:'+'a'*12,
                image_digest='sha256:'+'f'*64,source_revision='a'*40,source_snapshot='sha256:'+'b'*64,component=Path(root)/'driver.py',evidence=Path(root))

    def test_docker_manifest_id_is_not_used_as_runnable_reference(self):
        revision='a'*40;snapshot='sha256:'+'b'*64;index='sha256:'+'f'*64;manifest='sha256:'+'c'*64
        def run(name,argv,evidence,**kwargs):
            if 'create'in argv:
                self.assertIn('volt-easy-delivery-route-component@'+index,argv)
                self.assertNotIn(manifest,argv)
                raise RuntimeError('captured exact build-bound reference before execution')
            value='server-id'if'info'in argv else json.dumps([{'Id':manifest,'Os':'linux','Architecture':'amd64',
                'RepoDigests':['volt-easy-delivery-route-component@'+index],
                'Descriptor':{'digest':manifest,'mediaType':'application/vnd.oci.image.manifest.v1+json',
                    'size':123,'platform':{'os':'linux','architecture':'amd64'}},
                'Config':{'Labels':{'org.opencontainers.image.revision':revision,'org.volt.compose.source-snapshot':snapshot}}}])
            return subprocess.CompletedProcess(argv,0,value,'')
        with tempfile.TemporaryDirectory()as root,patch.dict('os.environ',{'DOCKER_HOST':'unix:///fixed'}),patch('tools.compose_release_qualification.run',side_effect=run):
            with self.assertRaisesRegex(RuntimeError,'captured exact build-bound reference'):
                qualify_protected_launch_component(image='volt-easy-delivery-route-component:'+'a'*12,
                    image_digest=index,source_revision=revision,source_snapshot=snapshot,
                    component=Path(root)/'driver.py',evidence=Path(root))
