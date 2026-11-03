import datetime as dt
import sys
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / "tools" / "release"))
from scan import validate_report
import scan


class ScannerPolicyTests(unittest.TestCase):
    def setUp(self):
        self.today = dt.date(2026, 11, 3)
        self.image_id = "sha256:" + "a" * 64
        self.report = {"SchemaVersion": 2, "ArtifactType": "container_image", "Metadata": {"ImageID": self.image_id, "OS": {"Family": "debian", "Name": "bookworm"}}, "Results": [{"Target": "debian", "Class": "os-pkgs", "Type": "debian", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2026-0001", "PkgName": "sample", "InstalledVersion": "1.0",
            "FixedVersion": "1.1", "Severity": "HIGH"
        }]}]}

    def test_fixable_high_fails_without_exact_exception(self):
        self.assertTrue(validate_report(self.report, [], self.today, self.image_id))

    def test_exact_approved_exception_with_30_day_expiry_passes(self):
        exception = [{"advisory": "CVE-2026-0001", "package": "sample", "version": "1.0",
                      "rationale": "temporary", "owner": "maintainer", "approval": "review-2",
                      "expires": "2026-12-03"}]
        self.assertEqual(validate_report(self.report, exception, self.today, self.image_id), [])

    def test_expired_exception_does_not_suppress_finding(self):
        exception = [{"advisory": "CVE-2026-0001", "package": "sample", "version": "1.0",
                      "rationale": "temporary", "owner": "maintainer", "approval": "review-2",
                      "expires": "2026-11-02"}]
        issues = validate_report(self.report, exception, self.today, self.image_id)
        self.assertTrue(any("expired" in issue for issue in issues))
        self.assertTrue(any("fixable HIGH" in issue for issue in issues))

    def test_scanner_process_failure_fails_closed(self):
        with TemporaryDirectory() as temp:
            temp = Path(temp)
            exceptions = temp / "exceptions.json"
            exceptions.write_text(json.dumps({"exceptions": []}))
            output = temp / "report.json"
            calls = [SimpleNamespace(returncode=0, stdout="Version: 0.76.1\n", stderr=""),
                     SimpleNamespace(returncode=2, stdout="", stderr="database download failed")]
            with patch.object(scan.shutil, "which", return_value="/pinned/trivy") as _, \
                 patch.object(scan.subprocess, "run", side_effect=calls) as run:
                # Exercise the CLI entry point so scanner failures cannot be hidden by report parsing.
                with patch.object(sys, "argv", ["scan.py", "--image", self.image_id, "--expected-image-id", self.image_id, "--exceptions", str(exceptions), "--output", str(output)]):
                    self.assertEqual(scan.main(), 2)
            self.assertEqual(run.call_count, 2)
            self.assertFalse(output.exists())
            self.assertIn("database download failed", output.with_suffix(".json.diagnostics.txt").read_text())

    def test_actual_cli_rejects_partial_or_wrong_image_report_and_retains_full_json(self):
        with TemporaryDirectory() as temp:
            temp = Path(temp); exceptions = temp / "exceptions.json"; exceptions.write_text('{"exceptions":[]}')
            output = temp / "report.json"
            partial = {"Metadata": {"OS": {"Family": "debian"}}}
            calls = [SimpleNamespace(returncode=0, stdout="Version: 0.76.1\n", stderr=""),
                     SimpleNamespace(returncode=0, stdout="scanner complete\n", stderr="")]
            def scanner_run(command, **kwargs):
                item = calls.pop(0)
                if "--version" not in command:
                    output.write_text(json.dumps(partial))
                return item
            with patch.object(scan.shutil, "which", return_value="/pinned/trivy"), patch.object(scan.subprocess, "run", side_effect=scanner_run):
                with patch.object(sys, "argv", ["scan.py", "--image", self.image_id, "--expected-image-id", self.image_id, "--exceptions", str(exceptions), "--output", str(output)]):
                    self.assertEqual(scan.main(), 1)
            self.assertTrue(output.is_file())
            self.assertIn("Metadata", output.read_text())
            self.assertIn("scanner complete", output.with_suffix(".json.diagnostics.txt").read_text())

    def test_report_wrong_immutable_image_is_rejected(self):
        wrong = json.loads(json.dumps(self.report)); wrong["Metadata"]["ImageID"] = "sha256:" + "b" * 64
        self.assertTrue(any("differs" in x for x in validate_report(wrong, [], self.today, self.image_id)))


if __name__ == "__main__":
    unittest.main()
