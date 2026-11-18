from __future__ import annotations

import json
import unittest
from pathlib import Path
import ast
import subprocess
import sys
import tempfile

from tools.compose_release_qualification import (SUPPORTED_IMAGE_VERSIONS, SUPPORTED_RELEASE_VERSIONS, init_command,
    admit_bundle_version, platform_from_image_inspect, qualification_release_metadata,
    qualification_scope, verified_bundle_version)


class ComposeQualificationPlatformTests(unittest.TestCase):
    def test_scope_uses_actual_runner_context_not_release_version(self):
        self.assertEqual(qualification_scope(version="0.1.0-rc.2", development_fixture=False, environment={}),
                         "local_synthetic_rc2")
        self.assertEqual(qualification_scope(version="0.1.0-rc.2", development_fixture=False, environment={
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}),
            "hosted_rc2_release")
        self.assertEqual(qualification_scope(version="0.1.0-rc.2", development_fixture=False, environment={
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}),
            "local_synthetic_rc2")
        self.assertEqual(qualification_scope(version="0.1.0-rc.2", development_fixture=True, environment={
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}),
            "development_fixture")
        self.assertEqual(qualification_scope(version="0.1.0-demo", development_fixture=True, environment={}),
                         "development_fixture")

    def test_rc3_scopes_follow_execution_environment_and_keep_rc2_names_unchanged(self):
        self.assertEqual(qualification_scope(version="0.1.0-rc.3", development_fixture=False,
            environment={}), "local_synthetic_rc3")
        self.assertEqual(qualification_scope(version="0.1.0-rc.3", development_fixture=False,
            environment={"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}),
            "hosted_rc3_release")
        with self.assertRaisesRegex(ValueError, "supported RC2 or RC3"):
            qualification_scope(version="0.1.0-rc.4", development_fixture=False, environment={})

    def test_release_version_allowlist_and_verified_bundle_version(self):
        self.assertEqual(SUPPORTED_RELEASE_VERSIONS, ("0.1.0-rc.2", "0.1.0-rc.3"))
        self.assertEqual(SUPPORTED_IMAGE_VERSIONS, ("0.1.0-rc.2", "0.1.0-rc.3", "0.1.0-demo"))
        self.assertEqual(admit_bundle_version("verified_version=0.1.0-rc.2 files=8", "0.1.0-rc.2"),
                         "0.1.0-rc.2")
        self.assertEqual(admit_bundle_version("verified_version=0.1.0-rc.3 files=10", "0.1.0-rc.3"),
                         "0.1.0-rc.3")
        self.assertEqual(admit_bundle_version("verified_version=0.1.0-rc.3 files=10", "0.1.0-demo",
            development_fixture=True), "0.1.0-rc.3")
        self.assertEqual(verified_bundle_version("verified_version=0.1.0-rc.3 files=10 sha256=" + "a" * 64),
                         "0.1.0-rc.3")
        with self.assertRaisesRegex(RuntimeError, "supported release version"):
            verified_bundle_version("verified_version=0.1.0-rc.4 files=10")
        with self.assertRaisesRegex(RuntimeError, "fixed RC2, RC3 and explicit demo fixture"):
            admit_bundle_version("verified_version=0.1.0-rc.3 files=10", "0.1.0-rc.4")
        with self.assertRaisesRegex(RuntimeError, "requires explicit development-fixture"):
            admit_bundle_version("verified_version=0.1.0-rc.3 files=10", "0.1.0-demo")

    def test_rc3_evidence_records_actual_bundle_and_image_metadata_separately(self):
        row = qualification_release_metadata(requested_version="0.1.0-demo",
            bundle_version="0.1.0-rc.3", image_version="0.1.0-demo",
            image_id="sha256:" + "a" * 64, platform="linux/arm64",
            source_revision="b" * 40, source_snapshot="sha256:" + "c" * 64,
            bundle_sha256="d" * 64, scope="hosted_rc3_release")
        self.assertEqual(row["release_version"], "0.1.0-rc.3")
        self.assertEqual(row["requested_image_version"], "0.1.0-demo")
        self.assertEqual(row["bundle_version"], "0.1.0-rc.3")
        self.assertEqual(row["image_version"], "0.1.0-demo")
        self.assertEqual(row["qualification_scope"], "hosted_rc3_release")
        self.assertEqual(row["platform"], "linux/arm64")
        self.assertEqual(row["source_revision"], "b" * 40)

    def test_bundle_version_mismatch_is_rejected_by_runner_before_instance_creation(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(prefix="compose-qual-version-") as temp_dir:
            base = Path(temp_dir)
            bundle = base / "volt-compose.tar.gz"
            build = subprocess.run([sys.executable, str(root / "tools/build_compose_bundle.py"),
                "build", "--output", str(bundle)], text=True, capture_output=True)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            private_tmp = base / "private"; private_tmp.mkdir()
            bundle_tmp = base / "extracted"; bundle_tmp.mkdir()
            evidence = base / "evidence"
            result = subprocess.run([sys.executable, str(root / "tools/compose_release_qualification.py"),
                "--image-id", "sha256:" + "a" * 64, "--source-snapshot", "sha256:" + "b" * 64,
                "--source-commit", "c" * 40, "--version", "0.1.0-rc.2", "--bundle", str(bundle),
                "--evidence", str(evidence), "--private-tmp", str(private_tmp), "--bundle-tmp", str(bundle_tmp)],
                text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requested release 0.1.0-rc.2 does not match verified Compose bundle 0.1.0-rc.3",
                          result.stderr)
            self.assertTrue((evidence / "bundle-verify.exit").is_file())
            self.assertEqual(list(private_tmp.iterdir()), [], "mismatch must fail before admin/instance setup")
            self.assertEqual(list(bundle_tmp.iterdir()), [], "mismatch must fail before bundle extraction")
            self.assertFalse((evidence / "init.exit").exists())

    def test_unsupported_release_version_fails_before_evidence_or_instance_setup(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(prefix="compose-qual-unsupported-") as temp_dir:
            base = Path(temp_dir)
            evidence = base / "evidence"
            private_tmp = base / "private"; private_tmp.mkdir()
            bundle_tmp = base / "extracted"; bundle_tmp.mkdir()
            result = subprocess.run([sys.executable, str(root / "tools/compose_release_qualification.py"),
                "--image-id", "sha256:" + "a" * 64, "--source-snapshot", "sha256:" + "b" * 64,
                "--source-commit", "c" * 40, "--version", "0.1.0-rc.4", "--bundle", str(base / "missing.tar.gz"),
                "--evidence", str(evidence), "--private-tmp", str(private_tmp), "--bundle-tmp", str(bundle_tmp)],
                text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid choice", result.stderr)
            self.assertFalse(evidence.exists())
            self.assertEqual(list(private_tmp.iterdir()), [])
            self.assertEqual(list(bundle_tmp.iterdir()), [])

    def test_demo_image_version_requires_explicit_development_fixture_flag(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(prefix="compose-qual-demo-guard-") as temp_dir:
            base = Path(temp_dir)
            evidence = base / "evidence"
            private_tmp = base / "private"; private_tmp.mkdir()
            bundle_tmp = base / "extracted"; bundle_tmp.mkdir()
            result = subprocess.run([sys.executable, str(root / "tools/compose_release_qualification.py"),
                "--image-id", "sha256:" + "a" * 64, "--source-snapshot", "sha256:" + "b" * 64,
                "--source-commit", "c" * 40, "--version", "0.1.0-demo", "--bundle", str(base / "missing.tar.gz"),
                "--evidence", str(evidence), "--private-tmp", str(private_tmp), "--bundle-tmp", str(bundle_tmp)],
                text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("0.1.0-demo requires --development-fixture", result.stderr)
            self.assertFalse(evidence.exists())
            self.assertEqual(list(private_tmp.iterdir()), [])
            self.assertEqual(list(bundle_tmp.iterdir()), [])

    def test_platform_from_image_config_admits_both_supported_architectures(self):
        for architecture, platform in (("amd64", "linux/amd64"), ("arm64", "linux/arm64")):
            with self.subTest(platform=platform):
                output = json.dumps([{"Os": "linux", "Architecture": architecture}])
                self.assertEqual(platform_from_image_inspect(output, platform), platform)

    def test_platform_admission_rejects_unsupported_and_mismatched_metadata(self):
        unsupported = json.dumps([{"Os": "linux", "Architecture": "ppc64le"}])
        with self.assertRaisesRegex(RuntimeError, "not supported"):
            platform_from_image_inspect(unsupported)
        amd64 = json.dumps([{"Os": "linux", "Architecture": "amd64"}])
        with self.assertRaisesRegex(RuntimeError, "disagrees"):
            platform_from_image_inspect(amd64, "linux/arm64")

    def test_platform_admission_rejects_ambiguous_or_malformed_inspection(self):
        with self.assertRaisesRegex(RuntimeError, "exactly one image"):
            platform_from_image_inspect("[]")
        with self.assertRaisesRegex(RuntimeError, "valid JSON"):
            platform_from_image_inspect("not-json")

    def test_installer_command_receives_the_admitted_platform(self):
        command = init_command(["python", "setup.py"], Path("/tmp/volt-demo"), "volt-demo",
                              [18080, 18081, 18090], "sha256:" + "a" * 64, "linux/arm64")
        self.assertEqual(command[command.index("--platform") + 1], "linux/arm64")
        self.assertEqual(command[command.index("--demo-admin-username") + 1], "qualification-admin")

    def test_installer_command_rejects_platform_outside_package_contract(self):
        with self.assertRaisesRegex(RuntimeError, "not supported"):
            init_command(["python", "setup.py"], Path("/tmp/volt-demo"), "volt-demo",
                         [18080, 18081, 18090], "sha256:" + "a" * 64, "linux/ppc64le")

    def test_maintained_qualification_imports_password_generator_and_retains_secret_until_cleanup(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / "tools/compose_release_qualification.py").read_text()
        tree = ast.parse(source)
        imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
            for alias in node.names}
        self.assertIn("secrets", imports)
        self.assertIn('qualification_password.unlink(missing_ok=True)', source)
        self.assertIn('"--password-file",str(qualification_password)', source)
        self.assertIn('del password_value', source)

    def test_browser_smoke_uses_password_login_for_fresh_sessions_without_fixture_bypass(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / "tools/g7_local_preview_smoke.mjs").read_text()
        self.assertIn("readFile(arg('--password-file')", source)
        self.assertIn("getByLabel('Username').fill(username)", source)
        self.assertIn("getByLabel('Password').fill(password)", source)
        self.assertNotIn("VOLT_SMOKE_FIXTURE_SUBJECT", source)
        revocation = source.split("const revoked=await waitForSession(page,{status:401});", 1)[1].split("const after=", 1)[0]
        self.assertIn("await page.reload({waitUntil:'domcontentloaded'})", revocation)
        self.assertLess(revocation.index("await page.reload"),
            revocation.index("getByRole('link',{name:/sign in/i})"))
        self.assertIn('"--password-file",str(qualification_password)',
            (root / "tools/compose_release_qualification.py").read_text())


    def test_session_transition_poll_awaits_status_and_rejects_false_pass(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / "tools/g7_local_preview_smoke.mjs").read_text()
        helper = source.split("// SESSION_POLL_START", 1)[1].split("// SESSION_POLL_END", 1)[0]
        script = helper + r'''
const assert=require('node:assert/strict');
(async()=>{
 let calls=0;
 const states=[{status:200,authenticated:true},{status:200,authenticated:true},{status:401,authenticated:false}];
 const page={evaluate:async()=>{calls++;return states.shift();}};
 assert.deepEqual(await waitForSession(page,{status:401,intervalMs:1}),{status:401,authenticated:false});
 assert.equal(calls,3,'must not accept the first 200 as revoked');
 let signedInCalls=0;
 await waitForSession({evaluate:async()=>++signedInCalls===1?{status:200,authenticated:false}:{status:200,authenticated:true}},
   {status:200,authenticated:true,intervalMs:1});
 assert.equal(signedInCalls,2,'must verify authenticated, not just HTTP 200');
 await assert.rejects(waitForSession({evaluate:async()=>({status:200,authenticated:true})},
   {status:401,timeoutMs:5,intervalMs:1}),/session_transition_not_observed/);
 console.log('PASS delayed revocation, delayed authentication, never-revoked timeout');
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        result = subprocess.run(["node", "-e", script], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS delayed revocation", result.stdout)


if __name__ == "__main__":
    unittest.main()
