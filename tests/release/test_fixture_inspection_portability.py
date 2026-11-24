"""No Docker execution: fixed preselected recipe + POSIX reached-path stub tests."""
import unittest
from tools.compose_release_qualification import fixture_inspect_argv
class FixtureInspectionPortabilityTests(unittest.TestCase):
    def test_old_and_new_capabilities_keep_same_exact_reference_and_platform_context(self):
        reference='127.0.0.1:46150/volt@sha256:'+'a'*64
        self.assertEqual(fixture_inspect_argv(reference,'linux/arm64',inspect_platform=False),['docker','image','inspect',reference])
        self.assertEqual(fixture_inspect_argv(reference,'linux/arm64',inspect_platform=True),['docker','image','inspect','--platform','linux/arm64',reference])
    def test_missing_nonboolean_or_foreign_context_is_not_a_fallback(self):
        reference='127.0.0.1:46150/volt@sha256:'+'a'*64
        for flag in (None,0,1,'false'):
            with self.assertRaises(ValueError):fixture_inspect_argv(reference,'linux/arm64',inspect_platform=flag)
        for ref,platform in (('caller/tag','linux/arm64'),(reference,'linux/riscv64')):
            with self.assertRaises(ValueError):fixture_inspect_argv(ref,platform,inspect_platform=False)
if __name__=='__main__':unittest.main()
