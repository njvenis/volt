import json
import subprocess
import sys
import tempfile
import unittest
import os
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

SCRIPT = Path(__file__).parents[2] / "tools" / "release" / "prepare.py"
sys.path.insert(0, str(SCRIPT.parent))
import prepare


class PreparationPolicyTests(unittest.TestCase):
    def run_prepare(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], text=True, capture_output=True)

    def test_rejects_wrong_version_and_missing_notices(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "source"
            notices = root / "notices"
            source.mkdir()
            notices.mkdir()
            wrong = self.run_prepare("--version", "0.1.0", "--source", source, "--notices", notices, "--image-id", "sha256:" + "a" * 64)
            self.assertNotEqual(wrong.returncode, 0)
            missing = self.run_prepare("--version", "0.1.0-rc.1", "--source", source, "--notices", notices, "--image-id", "sha256:" + "a" * 64)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("SBOMs", missing.stderr)

    def test_exception_must_be_exact_and_expire_within_30_days(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source, notices = root / "source", root / "notices"
            source.mkdir()
            notices.mkdir()
            exception = root / "exceptions.json"
            exception.write_text(json.dumps({"exceptions": [{
                "advisory": "CVE-2099-0001", "package": "sample", "version": "1.0",
                "rationale": "fixture", "owner": "maintainer", "approval": "review-1", "expires": "2099-02-01"
            }]}))
            result = self.run_prepare("--version", "0.1.0-rc.1", "--source", source, "--notices", notices,
                                      "--exception", exception, "--at", "2099-01-01", "--image-id", "sha256:" + "a" * 64)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("within 30 days", result.stderr)

    def test_rejects_expired_exception(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source, notices = root / "source", root / "notices"
            source.mkdir()
            notices.mkdir()
            exception = root / "exceptions.json"
            exception.write_text(json.dumps({"exceptions": [{
                "advisory": "CVE-2099-0001", "package": "sample", "version": "1.0",
                "rationale": "fixture", "owner": "maintainer", "approval": "review-1", "expires": "2098-12-31"
            }]}))
            result = self.run_prepare("--version", "0.1.0-rc.1", "--source", source, "--notices", notices,
                                      "--exception", exception, "--at", "2099-01-01", "--image-id", "sha256:" + "a" * 64)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("within 30 days", result.stderr)

    def make_repo(self, root):
        source = root / "approved-source"; source.mkdir()
        subprocess.run(["git", "init", "-b", "main", str(source)], check=True, capture_output=True)
        (source / "README.md").write_text("source\n")
        subprocess.run(["git", "-C", str(source), "add", "README.md"], check=True)
        env = {**os.environ, "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        subprocess.run(["git", "-C", str(source), "commit", "-m", "fixture"], check=True, env=env, capture_output=True)
        commit = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        return source, commit

    def run_with_dependencies(self, source, notices, image_id, commit):
        real_run = subprocess.run
        calls = []
        image = [{"Id": image_id, "Config": {"Labels": {"org.opencontainers.image.revision": commit, "org.opencontainers.image.version": "0.1.0-rc.1"}}}]
        def run(command, *args, **kwargs):
            calls.append((command, kwargs))
            if "verify.py" in str(command): return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[:3] == ["docker", "image", "inspect"]: return SimpleNamespace(returncode=0, stdout=json.dumps(image), stderr="")
            return real_run(command, *args, **kwargs)
        with patch.object(prepare.subprocess, "run", side_effect=run):
            with patch.object(sys, "argv", [str(SCRIPT), "--version", "0.1.0-rc.1", "--source", str(source), "--notices", str(notices), "--image-id", image_id, "--docker", "docker"]):
                result = prepare.main()
        return result, calls

    def test_actual_entrypoint_binds_git_and_notice_verification_to_source_image(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source, commit = self.make_repo(root)
            notices = root / "notices"; notices.mkdir(); (notices / "sbom.syft.json").write_text("{}")
            (notices / "sbom.spdx.json").write_text("{}")
            image_id = "sha256:" + "a" * 64
            result, calls = self.run_with_dependencies(source, notices, image_id, commit)
            self.assertEqual(result, 0)
            git_calls = [command for command, _ in calls if command and command[0] == "git"]
            self.assertTrue(git_calls)
            self.assertTrue(all("-C" in command and str(source.resolve()) in command for command in git_calls))
            notice_call = next(command for command, _ in calls if "verify.py" in str(command))
            self.assertEqual(notice_call[-2:], ["--image", image_id])

    def test_actual_entrypoint_rejects_non_main_source_and_existing_version_tag(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); source,commit=self.make_repo(root); notices=root/"notices"; notices.mkdir()
            (notices/"sbom.syft.json").write_text("{}"); (notices/"sbom.spdx.json").write_text("{}")
            image_id="sha256:"+"a"*64
            subprocess.run(["git","-C",str(source),"checkout","-b","feature"],check=True,capture_output=True)
            real_run=subprocess.run
            def run(command,*args,**kwargs):
                if "verify.py" in str(command): return SimpleNamespace(returncode=0,stdout="",stderr="")
                if command[:3]==["docker","image","inspect"]: return SimpleNamespace(returncode=0,stdout=json.dumps([{"Id":image_id,"Config":{"Labels":{"org.opencontainers.image.revision":commit,"org.opencontainers.image.version":"0.1.0-rc.1"}}}]),stderr="")
                return real_run(command,*args,**kwargs)
            argv=[str(SCRIPT),"--version","0.1.0-rc.1","--source",str(source),"--notices",str(notices),"--image-id",image_id]
            with patch.object(prepare.subprocess,"run",side_effect=run),patch.object(sys,"argv",argv):
                with self.assertRaises(SystemExit): prepare.main()
            subprocess.run(["git","-C",str(source),"checkout","main"],check=True,capture_output=True)
            subprocess.run(["git","-C",str(source),"tag","v0.1.0-rc.1"],check=True)
            with patch.object(prepare.subprocess,"run",side_effect=run),patch.object(sys,"argv",argv):
                with self.assertRaises(SystemExit): prepare.main()

    def test_actual_entrypoint_rejects_image_source_label_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); source,commit=self.make_repo(root); notices=root/"notices"; notices.mkdir()
            (notices/"sbom.syft.json").write_text("{}"); (notices/"sbom.spdx.json").write_text("{}")
            image_id="sha256:"+"a"*64; real_run=subprocess.run
            def run(command,*args,**kwargs):
                if "verify.py" in str(command): return SimpleNamespace(returncode=0,stdout="",stderr="")
                if command[:3]==["docker","image","inspect"]: return SimpleNamespace(returncode=0,stdout=json.dumps([{"Id":image_id,"Config":{"Labels":{"org.opencontainers.image.revision":"b"*40,"org.opencontainers.image.version":"0.1.0-rc.1"}}}]),stderr="")
                return real_run(command,*args,**kwargs)
            argv=[str(SCRIPT),"--version","0.1.0-rc.1","--source",str(source),"--notices",str(notices),"--image-id",image_id]
            with patch.object(prepare.subprocess,"run",side_effect=run),patch.object(sys,"argv",argv):
                with self.assertRaises(SystemExit): prepare.main()

    def test_actual_entrypoint_rejects_unrelated_non_git_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); unrelated = root / "unrelated"; unrelated.mkdir()
            notices = root / "notices"; notices.mkdir(); (notices / "sbom.syft.json").write_text("{}")
            (notices / "sbom.spdx.json").write_text("{}")
            image_id = "sha256:" + "a" * 64
            real_run = subprocess.run; calls=[]
            def run(command, *args, **kwargs):
                calls.append(command)
                if "verify.py" in str(command): return SimpleNamespace(returncode=0,stdout="",stderr="")
                if command[:3] == ["docker", "image", "inspect"]: return SimpleNamespace(returncode=0,stdout="[]",stderr="")
                return real_run(command,*args,**kwargs)
            with patch.object(prepare.subprocess,"run",side_effect=run), patch.object(sys,"argv",[str(SCRIPT),"--version","0.1.0-rc.1","--source",str(unrelated),"--notices",str(notices),"--image-id",image_id]):
                with self.assertRaises(subprocess.CalledProcessError): prepare.main()
            self.assertTrue(any(command[:3] == ["git", "-C", str(unrelated.resolve())] for command in calls))


if __name__ == "__main__":
    unittest.main()
