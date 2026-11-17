from __future__ import annotations

import json
import unittest
from pathlib import Path
import ast
import subprocess

from tools.compose_release_qualification import init_command, platform_from_image_inspect, qualification_scope


class ComposeQualificationPlatformTests(unittest.TestCase):
    def test_scope_uses_actual_runner_context_not_release_version(self):
        self.assertEqual(qualification_scope(development_fixture=False, environment={}),
                         "local_synthetic_rc2")
        self.assertEqual(qualification_scope(development_fixture=False, environment={
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}),
            "hosted_rc2_release")
        self.assertEqual(qualification_scope(development_fixture=False, environment={
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}),
            "local_synthetic_rc2")
        self.assertEqual(qualification_scope(development_fixture=True, environment={
            "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}),
            "development_fixture")

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
