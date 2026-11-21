"""Fixed TEST controller safety and real signed-source preflight branches.

No crypto or image authentication credit from these synthetic unit fixtures.
"""
from pathlib import Path
import copy
import os
import shutil
import subprocess
import tempfile
import unittest

from tools.compose_release_qualification import guard_extra_qualification_network, unsupported_upgrade_test_entry, network_snapshot_projection

ROOT=Path(__file__).resolve().parents[2]
GUARD='case "$action" in verify-cache|stop|start|status|logs|diagnose|setup|backup-record|backup-status|restore-provision|restore-admit|destroy) ;; *) fail "unsupported fixed lifecycle action" ;; esac'


class PublicFailclosedQualificationTests(unittest.TestCase):
    def test_extra_network_guard_rejects_foreign_attachment_identity_and_egress(self):
        row={'Id':'a'*64,'Name':'volt-easy-delivery-extra-test','Driver':'bridge','Internal':True,'Options':{},'Labels':{
            'volt.compose.owner-token':'owner','volt.delivery.project':'project','volt.delivery.test':'test'},'Containers':{'b'*64:{}}}
        expected={'network_id':'a'*64,'owner':'owner','project':'project','test_id':'test','api_id':'b'*64}
        guard_extra_qualification_network(row,**expected)
        for field,value in [('Id','foreign'),('Driver','overlay'),('Internal',False),('Options',{'device':'/private'}),('Containers',{'foreign':{}}),('Labels',{'volt.compose.owner-token':'foreign'})]:
            with self.subTest(field=field),self.assertRaises(RuntimeError):guard_extra_qualification_network({**row,field:value},**expected)
        empty={**row,'Containers':{}};guard_extra_qualification_network(empty,**expected)
        exact_defaults={**row,'Options':{'com.docker.network.enable_ipv4':'true','com.docker.network.enable_ipv6':'false'}}
        guard_extra_qualification_network(exact_defaults,**expected)
        for bad in ({'com.docker.network.enable_ipv4':'false','com.docker.network.enable_ipv6':'false'},
                {**exact_defaults['Options'],'device':'/private'}, {'com.docker.network.enable_ipv6':'true'}):
            with self.subTest(options=bad),self.assertRaises(RuntimeError):guard_extra_qualification_network({**row,'Options':bad},**expected)

    def test_snapshot_projection_preserves_identities_and_rejects_duplicate_mounts(self):
        container={'Id':'actual','Image':'signed','ImageManifestDescriptor':{'digest':'child'},
            'Config':{'Labels':{'owner':'exact'}},'Mounts':[{'Destination':'/b','Source':'second'},{'Destination':'/a','Source':'first'}],
            'HostConfig':{'NetworkMode':'original'},'NetworkSettings':{'Networks':{'original':{}}},'State':{'Running':False,'StartedAt':'exact'}}
        volumes=[{'Name':name,'Driver':'local'}for name in ('b','a','c')]
        before=network_snapshot_projection(container,volumes)
        self.assertEqual(before,network_snapshot_projection({**container,'Mounts':list(reversed(container['Mounts']))},list(reversed(volumes))))
        self.assertNotEqual(before,network_snapshot_projection({**container,'Image':'changed'},volumes))
        self.assertNotEqual(before,network_snapshot_projection({**container,'State':{'Running':False,'StartedAt':'changed'}},volumes))
        with self.assertRaises(RuntimeError):network_snapshot_projection({**container,'Mounts':[container['Mounts'][0]]*2},volumes)
        with self.assertRaises(RuntimeError):network_snapshot_projection(container,[volumes[0]]*3)

    def test_negative_entry_changes_only_one_literal_guard_and_preserves_authentication(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);original=root/'original';destination=root/'negative'
            source='#!/bin/sh\nfixed_external_authentication_before_execution\n'+GUARD+'\nexec original_signed_launcher "$action"\n';original.write_text(source)
            unsupported_upgrade_test_entry(original,destination)
            self.assertEqual(destination.read_text().replace('|destroy|upgrade)','|destroy)'),source)
            self.assertEqual(destination.stat().st_mode&0o777,0o700)
            for bad in ('missing guard',source+GUARD):
                original.write_text(bad)
                with self.assertRaisesRegex(RuntimeError,'absent/ambiguous'):unsupported_upgrade_test_entry(original,root/'unwritten')
                self.assertFalse((root/'unwritten').exists())

    def test_nonnetwork_context_hits_real_launcher_preflight_without_a_Docker_call(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);docker=root/'docker';calls=root/'calls'
            docker.write_text('#!/bin/sh\nprintf attempted >"$CALLS"\nexit 97\n');docker.chmod(0o700)
            result=subprocess.run(['/bin/sh',str(ROOT/'deploy/compose/launcher.sh'),'status'],capture_output=True,text=True,
                env={'PATH':str(root)+os.pathsep+os.environ['PATH'],'HOME':str(root),'CALLS':str(calls),'DOCKER_HOST':'blocked-nonnetwork-context://sentinel'})
            self.assertEqual(result.returncode,1)
            self.assertIn('volt installer: remote Docker contexts are unsupported because instance bind paths must exist on this host',result.stderr.splitlines())
            self.assertFalse(calls.exists());self.assertEqual(result.stdout,'')

    def test_missing_Docker_hits_real_launcher_preflight_without_any_candidate_execution(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);(root/'dirname').symlink_to(shutil.which('dirname'))
            result=subprocess.run(['/bin/sh',str(ROOT/'deploy/compose/launcher.sh'),'status'],capture_output=True,text=True,env={'PATH':str(root),'HOME':str(root)})
            self.assertEqual(result.returncode,1)
            self.assertEqual(result.stderr,'volt installer: required host command is missing: docker\n')
            self.assertEqual(result.stdout,'')
