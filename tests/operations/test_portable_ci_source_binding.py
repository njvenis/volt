from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE_EXPR = "${{ github.event.pull_request.head.sha || github.sha }}"


class PortableCISourceBindingTests(unittest.TestCase):
    def test_all_source_build_and_index_jobs_checkout_and_enforce_one_selected_revision(self):
        source = (ROOT / ".github/workflows/ci.yml").read_text()
        jobs = source.split("jobs:\n", 1)[1]
        for name, next_name in (("checks", "verifier-native"),
                                ("verifier-native", "runtime-native-artifacts"),
                                ("runtime-native-artifacts", "runtime-local-index"),
                                ("runtime-local-index", None)):
            body = jobs.split(f"  {name}:\n", 1)[1]
            if next_name:
                body = body.split(f"\n  {next_name}:\n", 1)[0]
            with self.subTest(job=name):
                self.assertIn(f"SELECTED_SOURCE_SHA: {SOURCE_EXPR}", body)
                self.assertIn(f"ref: {SOURCE_EXPR}", body)
                self.assertIn('git rev-parse HEAD)" = "$SELECTED_SOURCE_SHA"', body)

    def test_native_artifacts_record_event_selected_checkout_and_archive_identity(self):
        source = (ROOT / ".github/workflows/ci.yml").read_text()
        for artifact in ("runtime-artifact", "verifier-artifact"):
            with self.subTest(artifact=artifact):
                self.assertIn(f'"$RUNNER_TEMP/{artifact}/source-revision.txt"', source)
                self.assertIn(f'"$RUNNER_TEMP/{artifact}/source-event-revision.txt"', source)
                self.assertIn(f'"$RUNNER_TEMP/{artifact}/source-selection.json"', source)
        self.assertIn('source-event-revision.txt")" = "$GITHUB_SHA"', source)
        self.assertIn('source-revision.txt")" = "$SELECTED_SOURCE_SHA"', source)
        self.assertIn('record["event_sha"] == os.environ["GITHUB_SHA"]', source)
        self.assertIn('record["source_snapshot"] == "sha256:"', source)

    def test_general_bundle_smoke_uses_an_explicit_local_fixture_not_release_assets(self):
        source = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("--verifier-reference", source)
        self.assertIn("--local-admission-fixture", source)
        self.assertIn("127.0.0.1:46150/volt-installer-verifier@sha256:", source)

    def test_native_index_has_no_racy_dependency_on_general_check_artifact(self):
        source = (ROOT / ".github/workflows/ci.yml").read_text()
        index = source.split("  runtime-local-index:\n", 1)[1]
        self.assertNotIn("volt-easy-portable-source-selection", index)
        self.assertNotIn("general-source-selection", index)
        self.assertIn("needs: [runtime-native-artifacts, verifier-native]", index)
        self.assertIn('test "$(git rev-parse HEAD)" = "$SELECTED_SOURCE_SHA"', index)
        self.assertIn('source-revision.txt")" = "$SELECTED_SOURCE_SHA"', index)


if __name__ == "__main__":
    unittest.main()
