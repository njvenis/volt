from __future__ import annotations

import json
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
