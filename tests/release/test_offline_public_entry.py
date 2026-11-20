"""POSIX entry ordering with substituted Docker; no crypto or activation claim."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from tools.compose_release_qualification import create_offline_fixture_entry, require_claimed_setup_denial

class OfflinePublicEntryTests(unittest.TestCase):
    def fixture(self, parent):
        state=parent/'state';state.mkdir(mode=0o700);(state/'instance.json').write_text('{}')
        anchor=parent/'state.installer-artifacts';anchor.mkdir(mode=0o700)
        closure=anchor/'originals';closure.mkdir(mode=0o700)
        package=closure/'package';package.mkdir(mode=0o700)
        launcher=package/'launcher.sh';launcher.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >"$ENTRY_LAUNCH_LOG"\nif [ "${ENTRY_TERMINAL_DENIAL:-0}" = 1 ]; then printf "%s\\n" "volt installer: initial setup is already claimed" >&2; exit 1; fi\nif [ "${ENTRY_TERMINAL_GENERIC:-0}" = 1 ]; then printf "%s\\n" "volt installer: local maintenance command failed" >&2; exit 1; fi\n');launcher.chmod(0o700)
        index=closure/'runtime-index/blobs/sha256';index.mkdir(parents=True);(index/('b'*64)).write_text('{}')
        fixture=parent/'independent';fixture.mkdir(mode=0o700)
        private=parent/'entry';private.mkdir(mode=0o700)
        admission={'fixture_directory':str(fixture),'verifier_reference':'127.0.0.1:46150/volt-installer-verifier@sha256:'+'a'*64,
            'image_reference':'127.0.0.1:46150/volt@sha256:'+'b'*64,'platform':'linux/amd64',
            'source_commit':'c'*40,'source_snapshot':'sha256:'+'d'*64,'bundle_version':'0.1.0-rc.4','docker_inspect_platform':False}
        wrapper=create_offline_fixture_entry(state=state,admission=admission,private=private)
        binaries=parent/'bin';binaries.mkdir();docker=binaries/'docker'
        docker.write_text('#!'+sys.executable+'\n'+'''import json,os,sys
args=sys.argv[1:]
with open(os.environ['ENTRY_DOCKER_LOG'],'a') as stream:stream.write(json.dumps(args)+'\\n')
if any(v in args for v in ('verify-attestation','verify-blob','--offline-artifacts')):
 print('Successful trusted Cosign authentication diagnostic',file=sys.stderr)
 if os.environ.get('ENTRY_HUGE_AUTH_DIAGNOSTIC')=='1':print('N'*70000,file=sys.stderr)
 if os.environ.get('ENTRY_CLAIMED_AUTH_TEXT')=='1':print('volt installer: initial setup is already claimed',file=sys.stderr)
if 'verify-attestation' in args and os.environ.get('ENTRY_FAIL')=='crafted':
 print('volt installer: initial setup is already claimed',file=sys.stderr);sys.exit(1)
if args[:2]==['image','inspect']:
 if '--platform'in args:sys.exit(125)
 print('[]')
if 'verify-attestation' in args and os.environ.get('ENTRY_FAIL')=='signature':sys.exit(31)
if '--offline-artifacts' in args and os.environ.get('ENTRY_FAIL')=='full':sys.exit(32)
''');docker.chmod(0o700)
        env={**os.environ,'PATH':str(binaries)+os.pathsep+os.environ['PATH'],'TMPDIR':str(private),
            'ENTRY_DOCKER_LOG':str(parent/'docker.jsonl'),'ENTRY_LAUNCH_LOG':str(parent/'launcher.log')}
        return state,closure,wrapper,env,admission
    def run_entry(self,wrapper,state,env,*args):
        return subprocess.run(['sh',str(wrapper),*args,'--directory',str(state)],env=env,text=True,capture_output=True)
    def test_full_admission_before_launcher_and_suffix_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent=Path(temporary);state,closure,wrapper,env,admission=self.fixture(parent)
            syntax=subprocess.run(['sh','-n',str(wrapper)],capture_output=True,text=True);self.assertEqual(syntax.returncode,0,syntax.stderr)
            result=subprocess.run(['sh',str(wrapper),'backup-record','--directory',str(state),'--backup-directory',str(parent/'backup $ proof')],env=env,text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual((parent/'launcher.log').read_text().splitlines(),['backup-record','--directory',str(state),'--backup-directory',str(parent/'backup $ proof')])
            commands=[json.loads(v) for v in (parent/'docker.jsonl').read_text().splitlines()]
            self.assertEqual(len(commands),6)
            self.assertTrue(all('verify-attestation' in v for v in commands[:2]))
            self.assertTrue(all('verify-blob' in v for v in commands[2:4]))
            self.assertEqual(commands[4][:2],['image','inspect'])
            self.assertIn('--offline-artifacts',commands[5]);self.assertIn('--require-installed-pin',commands[5])
            for command in commands:
                if command[0]=='run':
                    self.assertIn('--pull=never',command);self.assertEqual(command[command.index('--network')+1],'none')
            self.assertFalse(list(wrapper.parent.glob('volt-external-offline.*')))
    def test_existing_setup_and_status_actions_are_authenticated_before_signed_launcher(self):
        for action in ('setup', 'status'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as temporary:
                parent=Path(temporary);state,_closure,wrapper,env,_admission=self.fixture(parent)
                result=self.run_entry(wrapper,state,env,action);self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual((parent/'launcher.log').read_text().splitlines(),[action,'--directory',str(state)])
                (parent/'launcher.log').unlink();env['ENTRY_FAIL']='full'
                denied=self.run_entry(wrapper,state,env,action);self.assertEqual(denied.returncode,32,denied.stderr)
                self.assertFalse((parent/'launcher.log').exists())

    def test_crypto_or_full_graph_failure_prevents_shell(self):
        for stage,exitcode,count in [('signature',31,1),('full',32,6)]:
            with self.subTest(stage=stage),tempfile.TemporaryDirectory() as temporary:
                parent=Path(temporary);state,_closure,wrapper,env,_admission=self.fixture(parent);env['ENTRY_FAIL']=stage
                result=self.run_entry(wrapper,state,env,'stop');self.assertEqual(result.returncode,exitcode,result.stderr)
                self.assertFalse((parent/'launcher.log').exists());self.assertEqual(len((parent/'docker.jsonl').read_text().splitlines()),count)
    def test_pre_extraction_full_verification_without_journal_has_no_shell(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent=Path(temporary);state,_closure,wrapper,env,_admission=self.fixture(parent);(state/'instance.json').unlink();state.rmdir()
            result=self.run_entry(wrapper,state,env,'verify-cache');self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('external_full_graph_verified=1',result.stdout);self.assertFalse(state.exists());self.assertFalse((parent/'launcher.log').exists())
            commands=[json.loads(v) for v in (parent/'docker.jsonl').read_text().splitlines()];self.assertIn('--offline-artifacts',commands[-1]);self.assertNotIn('--require-installed-pin',commands[-1])
    def test_only_single_nonlinked_stage_can_be_selected_as_transport(self):
        for contradiction in ('multiple','symlink','none'):
            with self.subTest(contradiction=contradiction),tempfile.TemporaryDirectory() as temporary:
                parent=Path(temporary);state,closure,wrapper,env,_admission=self.fixture(parent);stage=closure.parent/'.originals.partial.A1b2C3d4';closure.rename(stage)
                if contradiction=='multiple':(closure.parent/'.originals.partial.B1b2C3d4').mkdir(mode=0o700)
                elif contradiction=='symlink':stage.rename(parent/'detached');stage.symlink_to(parent/'detached',target_is_directory=True)
                else:stage.rename(parent/'detached')
                result=self.run_entry(wrapper,state,env,'stop');self.assertNotEqual(result.returncode,0);self.assertFalse((parent/'docker.jsonl').exists());self.assertFalse((parent/'launcher.log').exists())
    def test_other_instance_and_new_install_refused_before_crypto(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent=Path(temporary);state,_closure,wrapper,env,_admission=self.fixture(parent)
            for arguments in [('install','--directory',str(state)),('stop','--directory',str(parent/'other')),('stop','--directory',str(state),'--directory',str(state))]:
                result=subprocess.run(['sh',str(wrapper),*arguments],env=env,text=True,capture_output=True);self.assertNotEqual(result.returncode,0)
            self.assertFalse((parent/'docker.jsonl').exists())

    def test_authentication_noise_is_private_and_true_terminal_claimed_denial_is_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent=Path(temporary);state,_closure,wrapper,env,_admission=self.fixture(parent)
            env['ENTRY_CLAIMED_AUTH_TEXT']='1';env['ENTRY_TERMINAL_DENIAL']='1'
            result=self.run_entry(wrapper,state,env,'setup');require_claimed_setup_denial(result)
            records=list((wrapper.parent/'public-offline-authentication').glob('entry.*/authentication.stderr'))
            self.assertEqual(len(records),1);raw=records[0].read_text();self.assertIn('Successful trusted Cosign',raw);self.assertIn('initial setup is already claimed',raw)
            self.assertLessEqual(records[0].stat().st_size,65536);self.assertEqual(records[0].stat().st_mode&0o777,0o600)
    def test_crafted_claimed_auth_failure_or_noise_without_backend_claim_cannot_be_credited(self):
        for failure in ('crafted','successful-noise-only'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temporary:
                parent=Path(temporary);state,_closure,wrapper,env,_admission=self.fixture(parent)
                env['ENTRY_CLAIMED_AUTH_TEXT']='1'
                if failure=='crafted':env['ENTRY_FAIL']='crafted'
                else:env['ENTRY_TERMINAL_GENERIC']='1'
                result=self.run_entry(wrapper,state,env,'setup')
                with self.assertRaisesRegex(RuntimeError,'not explicitly established'):require_claimed_setup_denial(result)
                if failure=='crafted':self.assertEqual(result.returncode,1);self.assertEqual(result.stderr,'external offline authentication failed\n');self.assertFalse((parent/'launcher.log').exists())
                else:self.assertEqual(result.stderr,'volt installer: local maintenance command failed\n')

    def test_authentication_diagnostics_remain_bounded_when_a_producer_is_noisy(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent=Path(temporary);state,_closure,wrapper,env,_admission=self.fixture(parent);env['ENTRY_HUGE_AUTH_DIAGNOSTIC']='1'
            result=subprocess.run(['sh',str(wrapper),'setup','--directory',str(state)],env=env,text=True,capture_output=True,timeout=15)
            with self.assertRaises(RuntimeError):require_claimed_setup_denial(result)
            for path in (wrapper.parent/'public-offline-authentication').glob('entry.*/authentication.stderr'):
                self.assertLessEqual(path.stat().st_size,65536)
