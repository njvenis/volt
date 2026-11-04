from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.release import verify_candidate_run
from tools.release import verify_candidate_artifact


class CandidateIdentityTests(unittest.TestCase):
    def test_candidate_run_requires_same_successful_main_source_and_artifact(self):
        sha = "a" * 40
        run = {"id": 123, "repository": {"full_name": "njvenis/volt"},
               "path": ".github/workflows/release.yml@refs/heads/main", "event": "workflow_dispatch",
               "head_branch": "main", "head_sha": sha, "status": "completed", "conclusion": "success"}
        artifact = {"artifacts": [{"id": 44, "name": f"volt-rc2-candidate-{sha}",
                                   "expired": False, "digest": "sha256:" + "b" * 64}]}
        with patch.object(verify_candidate_run, "api", side_effect=[run, artifact]), \
             patch.dict("os.environ", {"GH_TOKEN": "fixture-token"}), \
             patch("sys.argv", ["verify_candidate_run.py", "--run-id", "123", "--source", sha,
                                "--repository", "njvenis/volt"]), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(verify_candidate_run.main(), 0)

        run["head_sha"] = "c" * 40
        with patch.object(verify_candidate_run, "api", return_value=run), \
             patch.dict("os.environ", {"GH_TOKEN": "fixture-token"}), \
             patch("sys.argv", ["verify_candidate_run.py", "--run-id", "123", "--source", sha,
                                "--repository", "njvenis/volt"]), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(verify_candidate_run.main(), 2)

    def test_candidate_run_rejects_wrong_workflow_or_non_main_path_suffix(self):
        for path in (".github/workflows/other.yml@refs/heads/main",
                     ".github/workflows/release.yml@refs/heads/feature"):
            with self.subTest(path=path):
                sha = "a" * 40
                run = {"id": 123, "repository": {"full_name": "njvenis/volt"},
                       "path": path, "event": "workflow_dispatch", "head_branch": "main",
                       "head_sha": sha, "status": "completed", "conclusion": "success"}
                with patch.object(verify_candidate_run, "api", return_value=run), \
                     patch.dict("os.environ", {"GH_TOKEN": "fixture-token"}), \
                     patch("sys.argv", ["verify_candidate_run.py", "--run-id", "123", "--source", sha,
                                        "--repository", "njvenis/volt"]), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(verify_candidate_run.main(), 2)

    def test_candidate_artifact_rejects_source_snapshot_drift_before_image_import(self):
        import hashlib
        import json
        with tempfile.TemporaryDirectory(prefix="volt-candidate-identity-") as directory:
            root = Path(directory)
            (root / "image-id.txt").write_text("sha256:" + "a" * 64)
            (root / "source-snapshot.txt").write_text("sha256:" + "b" * 64)
            (root / "prepare-run-id.txt").write_text("123\n")
            (root / "source.tar").write_bytes(b"different source")
            with patch("sys.argv", ["verify_candidate_artifact.py", "--directory", directory,
                                    "--source", "d" * 40, "--prepare-run-id", "123"]), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(verify_candidate_artifact.main(), 2)

    def test_candidate_artifact_rejects_different_prepare_run_id(self):
        with tempfile.TemporaryDirectory(prefix="volt-candidate-run-binding-") as directory:
            (Path(directory) / "prepare-run-id.txt").write_text("123\n")
            with patch("sys.argv", ["verify_candidate_artifact.py", "--directory", directory,
                                    "--source", "d" * 40, "--prepare-run-id", "124"]), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(verify_candidate_artifact.main(), 2)


if __name__ == "__main__":
    unittest.main()
