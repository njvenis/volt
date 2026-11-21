"""Owned real UID1800/process profile fixtures; no native Docker/RO-mount proof."""
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from uvm.auth import route_check_records as rc
from tests.operations.test_route_check import ProcessFixture


def local_config(mode='https'):
    return {'schema_version':1,'installation_id':str(uuid.uuid4()),
        'public_origin':'https://127.0.0.1' if mode=='https' else 'http://127.0.0.1',
        'secret_source':{'kind':'encrypted_local_v1','secret_source_id':str(uuid.uuid4()),'key_path':'/run/secrets/local-auth-key'},
        'bootstrap_delivery':{'kind':'private_file','path':'/tmp/fixture-capability'},'session_policy':{'ttl_seconds':3600},
        'trusted_ingress':{'mode':mode,'allowed_hosts':['127.0.0.1'],'allowed_peer_cidrs':['127.0.0.1/32']}}


def bootstrap(auth,verification='0'):
    # Readiness-specific fields of an already-admitted root-bootstrap fixture.
    # Exact72-key validation remains fixed protected Delivery launcher proof.
    return {'schema_version':1,'profile':rc.LAUNCH_PROFILE,'main_bind':'127.0.0.1','main_port':8080,
        'api_environment':{'UVM_AUTH_MODE':auth,'UVM_G7_VERIFICATION_ONLY':verification,
            'UVM_OIDC_DEPLOYMENT_MODE':'local' if auth=='local' else 'external',
            'UVM_API_HOST':'127.0.0.1','UVM_API_PORT':'8080','UVM_LOCAL_AUTH_CONFIG_FILE':'/etc/volt/local-auth.json'}}


def admission(config,raw):
    return {'schema_version':1,'profile':rc.RECOVERY_PROFILE,'document_type':'local_start_admission_v2',
        'installation_id':config['installation_id'],'journal_id':str(uuid.uuid4()),'restore_generation':0,
        'recovery_epoch_id':None,'image_id':'sha256:'+secrets.token_hex(32),'resources_sha256':secrets.token_hex(32),
        'initial_preparation':False,'local_auth_config_sha256':hashlib.sha256(raw).hexdigest()}


@unittest.skipUnless(os.geteuid()==0,'owned root/UID1800 process fixture')
class MainReadinessProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='volt-profile-owned-');os.chmod(self.temp.name,0o711)
    def tearDown(self):self.temp.cleanup()
    def test_all_eight_real_process_health_profiles_without_synthetic_boot(self):
        for profile in sorted(rc.READINESS_PROFILES):
            with self.subTest(profile=profile):
                f=ProcessFixture(Path(self.temp.name)/profile,readiness_profile=profile)
                try:
                    f.start()
                    with rc.locked_store(role='root') as store:
                        self.assertEqual(store.read_broker_ready(),profile.startswith('normal_'))
                        self.assertEqual(store.read_verification_health(),profile.startswith('verification_'))
                        self.assertEqual(store.current_state()['backend_ready'],profile==rc.OBSERVED_READINESS_PROFILE)
                        self.assertEqual(store.read_boot() is not None,profile==rc.OBSERVED_READINESS_PROFILE)
                        if profile!=rc.OBSERVED_READINESS_PROFILE:
                            with self.assertRaises(rc.RouteCheckError):rc.validate_supervision(store.read_supervisor())
                    if profile!=rc.OBSERVED_READINESS_PROFILE:
                        with self.assertRaises(AssertionError):f.command('boot_attempt')
                        with rc.locked_store(role='root') as store:self.assertIsNone(store.read_boot())
                    if profile in rc.LOCAL_BACKUP_PROFILES:self.assertEqual(rc.validate_local_backup_profile(f.launch),profile)
                    else:
                        with self.assertRaises(rc.RouteCheckError):rc.validate_local_backup_profile(f.launch)
                finally:f.close()
    def test_observed_https_missing_boot_is_not_normal_ready(self):
        f=ProcessFixture(Path(self.temp.name)/'missing-boot')
        try:
            f.start(ready=False);(f.directory/'api'/'boot.json').unlink()
            (Path(f.ready_temp.name)/'ready').touch(mode=0o600)
            with self.assertRaises(rc.RouteCheckError):f.session.acknowledge_parent_ready()
            with rc.locked_store(role='root') as store:self.assertFalse(store.read_broker_ready())
            self.assertIsNotNone(f.session.failure)
        finally:f.close()
    def test_closed_launch_and_start_versions_no_defaults_and_fence_projection(self):
        f=ProcessFixture(Path(self.temp.name)/'versions')
        try:
            f.start();self.assertEqual(f.launch['profile'],rc.LAUNCH_RECORD_PROFILE)
            for bad in ({k:v for k,v in f.launch.items() if k!='readiness_profile'},
                    {**f.launch,'profile':rc.LAUNCH_PROFILE},{**f.launch,'readiness_profile':'normal_local_http'}):
                with self.assertRaises(rc.RouteCheckError):rc.validate_record('launch',rc.canonical(bad))
            config=local_config();raw=rc.canonical(config);value=admission(config,raw)
            self.assertEqual(rc.validate_record('start_admission',rc.canonical(value)),value)
            for bad in ({k:v for k,v in value.items() if k!='local_auth_config_sha256'},
                    {**value,'document_type':'local_start_admission'},{**value,'local_auth_config_sha256':'invalid'}):
                with self.assertRaises(rc.RouteCheckError):rc.validate_record('start_admission',rc.canonical(bad))
            fence={k:value[k] for k in ('schema_version','profile','installation_id','journal_id','restore_generation','recovery_epoch_id')}
            self.assertEqual(len(fence),6);self.assertNotIn('local_auth_config_sha256',fence)
            self.assertEqual(fence['profile'],rc.RECOVERY_PROFILE)
        finally:f.close()
    def test_derivation_explicit_modes_digest_and_verification_issuer_separation(self):
        # Source pair / released-record readers are SUBSTITUTED here; actual
        # files and ST_RDONLY behavior are covered separately/native Delivery.
        for ingress in ('https','loopback'):
            config=local_config(ingress);raw=rc.canonical(config);value=admission(config,raw)
            with patch.object(rc,'_read_local_config_pair',return_value=(raw,config)),patch.object(rc,'_read_released_local_admission',return_value=value) as read:
                self.assertEqual(rc.derive_launch_readiness(bootstrap('local')),'normal_local_'+ingress)
                read.assert_called_once()
            with patch.object(rc,'_read_local_config_pair',return_value=(raw,config)),patch.object(rc,'_read_released_local_admission',side_effect=AssertionError('verification must not fabricate issuer')):
                self.assertEqual(rc.derive_launch_readiness(bootstrap('local','1')),'verification_local_'+ingress)
            with patch.object(rc,'_read_local_config_pair',return_value=(raw,config)),patch.object(rc,'_read_released_local_admission',return_value={**value,'local_auth_config_sha256':'0'*64}):
                with self.assertRaises(rc.RouteCheckError):rc.derive_launch_readiness(bootstrap('local'))
        with patch.object(rc,'_read_local_config_pair',side_effect=AssertionError('nonlocal local-custody read')):
            for auth in ('bearer','oidc'):
                for flag in ('0','1'):
                    self.assertEqual(rc.derive_launch_readiness(bootstrap(auth,flag)),('normal_' if flag=='0' else 'verification_')+auth)
        for flag in ('','true','2'):
            with self.assertRaises(rc.RouteCheckError):rc.derive_launch_readiness(bootstrap('bearer',flag))
        request=bootstrap('bearer');request['api_environment']['UVM_G7_RECOVERY_CONTROL_ONLY']='1'
        with self.assertRaises(rc.RouteCheckError):rc.derive_launch_readiness(request)

@unittest.skipUnless(os.geteuid()==0,'owned fixed-reader custody fixture')
class MainReadinessDescriptorTests(unittest.TestCase):
    def setUp(self):
        from contextlib import ExitStack
        self.temp=tempfile.TemporaryDirectory(prefix='volt-readiness-reader-owned-')
        self.root=Path(self.temp.name);self.stack=ExitStack()
        self.source_dir=self.root/'source';self.stage_dir=self.root/'stage';self.start_dir=self.root/'start'
        self.release_dir=self.root/'release';self.fence_dir=self.root/'fence'
        for directory in (self.source_dir,self.stage_dir,self.start_dir,self.release_dir,self.fence_dir):directory.mkdir(mode=0o700)
        self.fence_dir.chmod(0o710);os.chown(self.fence_dir,0,1800)
        self.source=self.source_dir/'local-auth.json';self.stage=self.stage_dir/'local-auth.json'
        self.recovery=self.stage_dir/'local-recovery.json';self.start=self.start_dir/'admission.json'
        self.release=self.release_dir/'host-start-release.json';self.fence=self.fence_dir/'fence.json'
        self.config=local_config('https');self.raw=rc.canonical(self.config);self.record=admission(self.config,self.raw)
        self.write(self.source,self.raw);self.write(self.stage,self.raw,owner=1800,group=1800)
        recovery={'schema_version':1,'profile':rc.RECOVERY_PROFILE,'installation_id':self.config['installation_id'],
            'issuer_key_id':'fixture','operator_key_id':'fixture','operator_id':'fixture',
            'issuer_public_key_file':'/fixture/issuer.pub','issuer_private_key_file':'/fixture/issuer.key',
            'operator_public_key_file':'/fixture/operator.pub','material_key_file':'/fixture/material.key',
            'restore_fence_file':'/run/volt-restore-fence/fence.json','restore_fence_custody':{'owner_uid':0,'runtime_gid':1800},
            'proof_store':'/fixture/proofs'}
        self.write(self.recovery,rc.canonical(recovery),owner=1800,group=1800)
        self.write(self.start,rc.canonical(self.record));self.write(self.release,rc.canonical(self.record))
        self.fence_value={k:self.record[k] for k in ('schema_version','profile','installation_id','journal_id','restore_generation','recovery_epoch_id')}
        self.write(self.fence,rc.canonical(self.fence_value),group=1800,mode=0o640)
        mapping={'/etc/volt/local-recovery.json':self.recovery,'/run/volt-start-admission':self.start_dir,
            '/run/uvm-maintenance/host-start-release.json':self.release,'/run/volt-restore-fence':self.fence_dir}
        # Explicit source-build fixed-path loader; no production alternate path.
        self.stack.enter_context(patch.object(rc,'Path',side_effect=lambda value:mapping.get(str(value),Path(value))))
        self.stack.enter_context(patch.object(rc,'LOCAL_CONFIG_SOURCE',self.source))
        self.stack.enter_context(patch.object(rc,'LOCAL_CONFIG_STAGE',self.stage))
        def fixture_parent(path):
            fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:rc._directory(fd,0,0,0o700)
            except BaseException:os.close(fd);raise
            return fd
        self.stack.enter_context(patch.object(rc,'_open_config_parent',side_effect=fixture_parent))
        self.real_statvfs=os.fstatvfs
    def tearDown(self):self.stack.close();self.temp.cleanup()
    def write(self,path,raw,*,owner=0,group=0,mode=0o600):
        path.write_bytes(raw);os.chown(path,owner,group);path.chmod(mode)
    def ro_fixture(self):
        # ONLY the kernel RO bit is substituted on this owned read-write /tmp
        # filesystem. Actual descriptors, bytes, modes, links and joins are real.
        from types import SimpleNamespace
        def statvfs(fd):
            actual=self.real_statvfs(fd)
            return SimpleNamespace(f_flag=actual.f_flag|os.ST_RDONLY) if os.fstat(fd).st_ino==self.source.stat().st_ino else actual
        return patch.object(rc.os,'fstatvfs',side_effect=statvfs)
    def test_real_descriptor_digest_source_stage_release_and_fence_positive(self):
        with self.ro_fixture():
            self.assertEqual(rc.derive_launch_readiness(bootstrap('local')),'normal_local_https')
            self.assertEqual(rc.load_runtime_admission(expected_image_id=self.record['image_id'],expected_resources_sha256=self.record['resources_sha256']),self.record)
        self.assertEqual(set(self.fence_value),{'schema_version','profile','installation_id','journal_id','restore_generation','recovery_epoch_id'})
    def test_actual_writable_mount_is_denied_no_flag_substitution(self):
        fd=os.open(self.source,os.O_RDONLY)
        try:self.assertFalse(self.real_statvfs(fd).f_flag&os.ST_RDONLY)
        finally:os.close(fd)
        with self.assertRaises(rc.RouteCheckError):rc.derive_launch_readiness(bootstrap('local'))
    def test_changed_valid_source_cannot_downgrade_expected_pin_on_relaunch(self):
        changed={**self.config,'public_origin':'http://127.0.0.1',
            'trusted_ingress':{**self.config['trusted_ingress'],'mode':'loopback'}}
        raw=rc.canonical(changed);self.write(self.source,raw);self.write(self.stage,raw,owner=1800,group=1800)
        before=self.start.read_bytes(),self.release.read_bytes()
        with self.ro_fixture():
            with self.assertRaises(rc.RouteCheckError):rc.derive_launch_readiness(bootstrap('local'))
            # Verification does NOT fabricate an installer issuer/release.
            self.assertEqual(rc.derive_launch_readiness(bootstrap('local','1')),'verification_local_loopback')
        self.assertEqual((self.start.read_bytes(),self.release.read_bytes()),before)
    def test_release_missing_changed_initial_or_old_digest_document_denies(self):
        for case in ('missing','changed','initial','old'):
            with self.subTest(case=case):
                self.write(self.start,rc.canonical(self.record));self.write(self.release,rc.canonical(self.record))
                if case=='missing':self.release.unlink()
                elif case=='changed':self.write(self.release,rc.canonical({**self.record,'local_auth_config_sha256':'0'*64}))
                elif case=='initial':
                    value={**self.record,'initial_preparation':True};self.write(self.start,rc.canonical(value));self.write(self.release,rc.canonical(value))
                else:
                    value={k:v for k,v in self.record.items() if k!='local_auth_config_sha256'};value['document_type']='local_start_admission'
                    self.write(self.start,rc.canonical(value));self.write(self.release,rc.canonical(value))
                with self.ro_fixture():
                    with self.assertRaises(rc.RouteCheckError):rc.derive_launch_readiness(bootstrap('local'))
                    self.assertEqual(rc.derive_launch_readiness(bootstrap('local','1')),'verification_local_https')
    def test_stage_mode_owner_symlink_hardlink_and_fence_projection_denials(self):
        original=self.source.read_bytes()
        for case in ('stage_bytes','stage_owner','source_mode','source_symlink','source_hardlink','fence_extra','fence_epoch'):
            with self.subTest(case=case):
                if self.source.is_symlink():self.source.unlink()
                link=self.source_dir/'extra-link'
                if link.exists():link.unlink()
                self.write(self.source,original);self.write(self.stage,original,owner=1800,group=1800)
                self.write(self.fence,rc.canonical(self.fence_value),group=1800,mode=0o640)
                if case=='stage_bytes':self.write(self.stage,original+b' ',owner=1800,group=1800)
                elif case=='stage_owner':os.chown(self.stage,0,0)
                elif case=='source_mode':self.source.chmod(0o644)
                elif case=='source_symlink':self.source.unlink();self.source.symlink_to(self.stage)
                elif case=='source_hardlink':os.link(self.source,link)
                elif case=='fence_extra':self.write(self.fence,rc.canonical({**self.fence_value,'local_auth_config_sha256':self.record['local_auth_config_sha256']}),group=1800,mode=0o640)
                else:self.write(self.fence,rc.canonical({**self.fence_value,'journal_id':str(uuid.uuid4())}),group=1800,mode=0o640)
                with self.ro_fixture():
                    with self.assertRaises(rc.RouteCheckError):rc.derive_launch_readiness(bootstrap('local'))
    def test_wrong_independent_image_resources_and_duplicate_config_deny(self):
        with self.ro_fixture():
            with self.assertRaises(rc.RouteCheckError):rc.load_runtime_admission(expected_image_id='sha256:'+'0'*64,expected_resources_sha256=self.record['resources_sha256'])
            with self.assertRaises(rc.RouteCheckError):rc.load_runtime_admission(expected_image_id=self.record['image_id'],expected_resources_sha256='0'*64)
        duplicate=self.raw[:-1]+b',"schema_version":1}'
        self.write(self.source,duplicate);self.write(self.stage,duplicate,owner=1800,group=1800)
        with self.ro_fixture():
            with self.assertRaises(rc.RouteCheckError):rc.derive_launch_readiness(bootstrap('local','1'))

    def test_issued_loopback_digest_supports_normal_http_without_https_boot(self):
        self.config['public_origin']='http://127.0.0.1';self.config['trusted_ingress']['mode']='loopback'
        raw=rc.canonical(self.config)
        value=admission(self.config,raw) # Explicit owned issuer fixture, not production pin refresh.
        # Keep the original six-field fence context while choosing fixture input.
        value.update({k:self.record[k] for k in ('journal_id','restore_generation','recovery_epoch_id','image_id','resources_sha256')})
        self.write(self.source,raw);self.write(self.stage,raw,owner=1800,group=1800)
        self.write(self.start,rc.canonical(value));self.write(self.release,rc.canonical(value))
        with self.ro_fixture():
            self.assertEqual(rc.derive_launch_readiness(bootstrap('local')),'normal_local_loopback')
            self.assertEqual(rc.load_runtime_admission(expected_image_id=value['image_id'],expected_resources_sha256=value['resources_sha256']),value)

    def test_early_reader_initial_and_no_release_never_weakens_released_reader(self):
        self.release.unlink()
        for initial in (False,True):
            with self.subTest(initial=initial):
                value={**self.record,'initial_preparation':initial};self.write(self.start,rc.canonical(value))
                before={path:path.read_bytes() for path in (self.source,self.stage,self.start,self.fence)}
                with self.ro_fixture():
                    self.assertEqual(rc.load_start_admission(expected_image_id=value['image_id'],expected_resources_sha256=value['resources_sha256']),value)
                    with self.assertRaises(rc.RouteCheckError):rc.load_runtime_admission(expected_image_id=value['image_id'],expected_resources_sha256=value['resources_sha256'])
                self.assertEqual({path:path.read_bytes() for path in before},before)
                self.assertFalse(self.release.exists())
        # Even a matching initial root file is not a released normal admission.
        self.write(self.release,self.start.read_bytes())
        with self.ro_fixture():
            self.assertTrue(rc.load_start_admission(expected_image_id=self.record['image_id'],expected_resources_sha256=self.record['resources_sha256'])['initial_preparation'])
            with self.assertRaises(rc.RouteCheckError):rc.load_runtime_admission(expected_image_id=self.record['image_id'],expected_resources_sha256=self.record['resources_sha256'])
    def test_early_reader_initial_old_sha_fence_custody_and_explicit_context_deny(self):
        for case in ('old','missing_sha','wrong_sha','initial_restored','fence','custody','image','resources'):
            with self.subTest(case=case):
                value={**self.record,'initial_preparation':True}
                self.write(self.start,rc.canonical(value));self.write(self.source,self.raw)
                self.write(self.fence,rc.canonical(self.fence_value),group=1800,mode=0o640)
                image=value['image_id'];resources=value['resources_sha256']
                if case=='old':self.write(self.start,rc.canonical({**value,'document_type':'local_start_admission'}))
                elif case=='missing_sha':self.write(self.start,rc.canonical({k:v for k,v in value.items() if k!='local_auth_config_sha256'}))
                elif case=='wrong_sha':self.write(self.start,rc.canonical({**value,'local_auth_config_sha256':'0'*64}))
                elif case=='initial_restored':self.write(self.start,rc.canonical({**value,'restore_generation':1,'recovery_epoch_id':str(uuid.uuid4())}))
                elif case=='fence':self.write(self.fence,rc.canonical({**self.fence_value,'journal_id':str(uuid.uuid4())}),group=1800,mode=0o640)
                elif case=='custody':self.source.chmod(0o644)
                elif case=='image':image='sha256:'+'0'*64
                else:resources='0'*64
                with self.ro_fixture():
                    with self.assertRaises(rc.RouteCheckError):rc.load_start_admission(expected_image_id=image,expected_resources_sha256=resources)
