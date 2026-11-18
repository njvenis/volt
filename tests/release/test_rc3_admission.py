"""Executable local contracts; these do not claim hosted/native qualification."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/release"))
sys.path.insert(0, str(ROOT / "tools"))
import archive
import build_compose_bundle
import rc3_candidate as candidate
import download_candidate
import github_release
import registry


class RC3AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="volt-rc3-contract-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        shutil.copytree(ROOT / "deploy/compose", self.source / "deploy/compose")
        (self.source / "tools/release").mkdir(parents=True)
        shutil.copyfile(ROOT / "tools/release/exceptions.example.json", self.source / "tools/release/exceptions.example.json")
        for name in candidate.NOTICE_SOURCES:
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        self.git("init", "-q", "-b", "main")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
        self.commit = self.git("rev-parse", "HEAD").strip()
        self.package = self.root / "candidate"
        self.package.mkdir()
        self.git("archive", "--format=tar", "--output", str(self.package / "source.tar"), "HEAD")
        self.git("bundle", "create", str(self.package / "source.bundle"), "HEAD")
        self.snapshot = "sha256:" + archive.sha(self.package / "source.tar")
        layer_buffer = io.BytesIO()
        with tarfile.open(fileobj=layer_buffer, mode="w") as layer:
            data=b"fixture"
            info=tarfile.TarInfo("fixture.txt"); info.size=len(data)
            layer.addfile(info,io.BytesIO(data))
        layer=layer_buffer.getvalue()
        config = {"os":"linux", "architecture":"amd64", "config":{"Labels":{
            "org.opencontainers.image.revision":self.commit, "org.opencontainers.image.version":candidate.VERSION,
            "org.volt.compose.source-snapshot":self.snapshot, "org.volt.compose-install.contract":"1",
            "org.volt.oidc-deployment-modes":"demo,external"}},
            "rootfs":{"type":"layers","diff_ids":["sha256:"+hashlib.sha256(layer).hexdigest()]}}
        raw=json.dumps(config).encode()
        self.image="sha256:"+hashlib.sha256(raw).hexdigest()
        with tarfile.open(self.package / "image.tar", "w") as image:
            rows={self.image[7:]+".json":raw,"layer.tar":layer,"manifest.json":json.dumps([
                {"Config":self.image[7:]+".json","RepoTags":["volt:fixture"],"Layers":["layer.tar"]}]).encode()}
            for name,data in rows.items():
                info=tarfile.TarInfo(name);info.size=len(data);image.addfile(info,io.BytesIO(data))
        for name,value in {"image-id.txt":self.image,"source-snapshot.txt":self.snapshot,"prepare-run-id.txt":"123"}.items():
            (self.package/name).write_text(value+"\n")
        with contextlib.redirect_stdout(io.StringIO()):
            build_compose_bundle.build(self.package / "compose-qualification.tar.gz", source_root=self.source)
        self.report={"SchemaVersion":2,"ArtifactType":"container_image", "Metadata":{"ImageID":self.image,
            "OS":{"Family":"debian","Name":"13"}},"Results":[{"Target":"fixture","Class":"os-pkgs","Type":"debian"}]}
        self.write_json("release-scan.json",self.report)
        (self.package/"release-scan.json.diagnostics.txt").write_text("fixture scan\n")
        (self.package/"notices").mkdir()
        self.write_json("notices/notice-manifest.json",{"image_id":self.image,"platform":"linux/amd64",
            "source_revision":self.commit,"source_files":[{"path":name,"sha256":archive.sha(self.source/name)} for name in candidate.NOTICE_SOURCES]})
        (self.package/"compose-evidence").mkdir()
        self.receipt={"result":"passed","qualification_scope":"hosted_rc3_release","release_version":candidate.VERSION,
            "requested_image_version":candidate.VERSION,"bundle_version":candidate.VERSION,"image_version":candidate.VERSION,
            "image_id":self.image,"platform":"linux/amd64","source_revision":self.commit,"source_snapshot":self.snapshot,
            "bundle_sha256":archive.sha(self.package/"compose-qualification.tar.gz"),"cold_backup_inventories":3,
            "execution_environment":{"GITHUB_ACTIONS":"true","RUNNER_ENVIRONMENT":"github-hosted"},
            **{key:"passed" for key in candidate.QUALIFICATION_PASSES}}
        self.write_json("compose-evidence/qualification.json",self.receipt)
        for suffix,value in (("exit","0\n"),("stdout","fixture cleanup\n"),("stderr","")):
            (self.package/f"compose-evidence/owned-cleanup.{suffix}").write_text(value)
        candidate.seal(self.package)

    def git(self,*args):
        return subprocess.check_output(["git","-C",str(self.source),*args],stderr=subprocess.PIPE,text=True)

    def write_json(self,name,value):
        (self.package/name).write_text(json.dumps(value))

    def verify(self):
        # Only external gpgv-heavy notice verification is substituted. Git bundle,
        # source archive, image/config/layers, bundle, receipt and scan execute here.
        real_run=subprocess.run
        def run(argv,**kwargs):
            if len(argv)>1 and argv[1] == str(ROOT/"tools/notices/verify.py"):
                return subprocess.CompletedProcess(argv,0)
            return real_run(argv,**kwargs)
        with patch.object(candidate.subprocess,"run",side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            return candidate.verify(self.package,self.commit,"123","linux/amd64",controller=self.source)

    def reject_before_registry(self,pattern):
        publish=Mock()
        with self.assertRaisesRegex((ValueError,subprocess.CalledProcessError),pattern):
            self.verify()
            publish()
        publish.assert_not_called()

    def test_complete_fixture_is_admitted_and_actual_image_layers_checked(self):
        self.assertEqual(self.verify()["image_config_id"],self.image)
        self.assertEqual(self.verify()["source_snapshot"],self.snapshot)

    def test_missing_extra_and_corrupt_inventory_fail_before_registry(self):
        original=(self.package/"source.bundle").read_bytes()
        (self.package/"source.bundle").unlink()
        self.reject_before_registry("closed top-level")
        (self.package/"source.bundle").write_bytes(original)
        (self.package/"extra.py").write_text("raise SystemExit(0)")
        self.reject_before_registry("closed top-level")
        (self.package/"extra.py").unlink()
        (self.package/"source.bundle").write_bytes(b"tampered")
        self.reject_before_registry("inventory/hash")

    def test_unexecutable_bundle_fails_even_after_inventory_resealed(self):
        (self.package/"source.bundle").write_bytes(b"not a git bundle")
        candidate.seal(self.package)
        self.reject_before_registry("git")

    def test_wrong_approved_source_and_tree_fail(self):
        (self.package/"source.tar").write_bytes(b"wrong tree")
        (self.package/"source-snapshot.txt").write_text("sha256:"+archive.sha(self.package/"source.tar"))
        candidate.seal(self.package)
        self.reject_before_registry("approved controller commit")

    def test_high_fixable_scan_rejected_even_with_correct_image_id(self):
        self.report["Results"][0]["Vulnerabilities"]=[{"VulnerabilityID":"CVE-fixture","PkgName":"fixture",
            "InstalledVersion":"1","Severity":"HIGH","FixedVersion":"2"}]
        self.write_json("release-scan.json",self.report);candidate.seal(self.package)
        self.reject_before_registry("fixable HIGH")

    def test_wrong_platform_receipt_cleanup_and_bundle_bindings_rejected(self):
        for field,value in (("platform","linux/arm64"),("bundle_sha256","0"*64),("result","failed"),
                            ("source_revision","a"*40),("qualification_scope","local_synthetic_rc3")):
            with self.subTest(field=field):
                doc={**self.receipt,field:value}
                self.write_json("compose-evidence/qualification.json",doc);candidate.seal(self.package)
                self.reject_before_registry("qualification receipt")
        self.write_json("compose-evidence/qualification.json",self.receipt)
        (self.package/"compose-evidence/owned-cleanup.exit").write_text("1\n");candidate.seal(self.package)
        self.reject_before_registry("owned cleanup")

    def test_self_consistent_modified_installer_is_not_approved_source(self):
        original=self.source/"deploy/compose/setup.py"
        original.write_text(original.read_text()+"\nraise SystemExit('attacker')\n")
        with contextlib.redirect_stdout(io.StringIO()):
            build_compose_bundle.build(self.package/"compose-qualification.tar.gz",source_root=self.source)
        candidate.seal(self.package)
        self.reject_before_registry("bundle source differs")

    def test_notice_source_hash_and_missing_source_rows_rejected(self):
        path=self.package/"notices/notice-manifest.json"
        original=json.loads(path.read_text())
        for rows in ([],[{**row,"sha256":"0"*64} for row in original["source_files"]]):
            path.write_text(json.dumps({**original,"source_files":rows}));candidate.seal(self.package)
            self.reject_before_registry("notice source")

    def test_missing_qualification_cannot_be_hidden_by_resealing(self):
        (self.package/"compose-evidence/qualification.json").unlink();candidate.seal(self.package)
        publish=Mock()
        with self.assertRaises(FileNotFoundError):
            self.verify();publish()
        publish.assert_not_called()


class TransferAndIdentityTests(unittest.TestCase):
    def test_zip_digest_and_closed_payload_checked_before_extraction(self):
        with tempfile.TemporaryDirectory() as work:
            root=Path(work);bundle=root/"candidate.zip"
            with zipfile.ZipFile(bundle,"w") as z:
                z.writestr("volt-rc3-candidate-amd64.tar.gz",b"fixture")
            expected="sha256:"+archive.sha(bundle)
            with self.assertRaisesRegex(ValueError,"API digest"):
                download_candidate.extract(bundle,"sha256:"+"0"*64,root/"wrong","volt-rc3-candidate-amd64.tar.gz")
            self.assertFalse((root/"wrong").exists())
            download_candidate.extract(bundle,expected,root/"good","volt-rc3-candidate-amd64.tar.gz")
            self.assertEqual((root/"good/volt-rc3-candidate-amd64.tar.gz").read_bytes(),b"fixture")
            with self.assertRaisesRegex(ValueError,"exactly"):
                download_candidate.extract(bundle,expected,root/"wrongarch","volt-rc3-candidate-arm64.tar.gz")

    def test_exact_github_absence_is_distinct_from_failure_or_existing_identity(self):
        for status,exit_code,body,accepted in ((404,1,'{"message":"Not Found"}',True),
            (403,1,'{"message":"Forbidden"}',False),(500,1,'{}',False),(200,0,'{}',False),
            (404,1,'{}',False),(0,1,'network error',False)):
            with self.subTest(status=status,body=body), patch.object(github_release.subprocess,"run",return_value=
                subprocess.CompletedProcess([],exit_code,f"HTTP/2.0 {status} status\n\n{body}","")):
                if accepted: github_release.require_absent("fixture")
                else:
                    with self.assertRaises(ValueError): github_release.require_absent("fixture")

    def test_index_requires_exact_platform_children(self):
        amd="sha256:"+"a"*64;arm="sha256:"+"b"*64
        doc={"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[
            {"digest":amd,"platform":{"os":"linux","architecture":"amd64"}},
            {"digest":arm,"platform":{"os":"linux","architecture":"arm64"}}]}
        registry.validate_index(doc,amd,arm)
        for field,value in (("digest",amd),("platform",{"os":"linux","architecture":"amd64"})):
            bad=copy.deepcopy(doc);bad["manifests"][1][field]=value
            with self.assertRaises(ValueError): registry.validate_index(bad,amd,arm)


class WorkflowExecutableSnippetTests(unittest.TestCase):
    def test_provenance_snippet_uses_only_its_declared_step_environment(self):
        import textwrap
        import re
        import provenance
        workflow=(ROOT/".github/workflows/release-rc3.yml").read_text()
        step=workflow.split("      - name: Publish exact retained images, create signed index, and verify immutable digests",1)[1].split("      - name:",1)[0]
        environment=step.split("        env:\n",1)[1].split("        run:",1)[0]
        values={"inputs.candidate_run_id":"123", "inputs.candidate_source_sha":"a"*40,
                "github.actor":"fixture", "github.token":"fixture-token"}
        declared={}
        for line in environment.splitlines():
            match=re.fullmatch(r"          ([A-Z_]+): \$\{\{ (.*?) \}\}",line)
            if match: declared[match[1]]=values[match[2]]
        self.assertEqual(declared["CANDIDATE_RUN_ID"],"123")
        code=textwrap.dedent(step.split("<<'PYPROV'\n",1)[1].split("          PYPROV",1)[0])
        with tempfile.TemporaryDirectory() as work:
            root=Path(work)
            (root/"identity-amd64.json").write_text(json.dumps({"artifact_id":44,"artifact_digest":"sha256:"+"b"*64}))
            (root/"rc3-amd64-transfer").mkdir()
            (root/"rc3-amd64-transfer/volt-rc3-candidate-amd64.tar.gz").write_bytes(b"admitted candidate fixture")
            env={"PATH":os.environ["PATH"],"RUNNER_TEMP":str(root),"GITHUB_SERVER_URL":"https://github.com",
                "GITHUB_REPOSITORY":"njvenis/volt","GITHUB_SHA":"c"*40,"GITHUB_RUN_ID":"456",
                "GITHUB_WORKFLOW_REF":provenance.RC3_WORKFLOW_REF,**declared}
            result=subprocess.run([sys.executable,"-",str(root/"provenance.json"),"amd64"],input=code,
                text=True,capture_output=True,env=env)
            self.assertEqual(result.returncode,0,result.stderr)
            provenance.validate(json.loads((root/"provenance.json").read_text()),"a"*40,
                expected_controller_commit="c"*40,expected_workflow_ref=provenance.RC3_WORKFLOW_REF)
            del env["CANDIDATE_RUN_ID"]
            result=subprocess.run([sys.executable,"-",str(root/"provenance.json"),"amd64"],input=code,
                text=True,capture_output=True,env=env)
            self.assertNotEqual(result.returncode,0)
            self.assertIn("CANDIDATE_RUN_ID",result.stderr)

    def test_native_build_commands_pass_exact_architecture_ce_pin(self):
        import re
        import textwrap
        workflow=(ROOT/".github/workflows/release-rc3.yml").read_text()
        native=workflow.split("  native_candidate:",1)[1].split("  retain_candidate:",1)[0]
        pin_line=next(line.strip() for line in native.splitlines() if line.strip().startswith("ce_image="))
        checks=next(line.strip() for line in native.splitlines() if "docker build --check" in line)
        # Select just the multiline Docker command, independent of previous job setup.
        command=native.split('          docker build --platform',1)[1].split('          docker image inspect',1)[0]
        command='docker build --platform '+textwrap.dedent(command)
        for arch in ("amd64","arm64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as work:
                root=Path(work);log=root/"docker.args"
                docker=root/"docker"
                docker.write_text('#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$DOCKER_ARGS"\n')
                docker.chmod(0o755)
                script=pin_line+'\nexport CE_IMAGE="$ce_image"\n'+checks+'\n'+command
                script=script.replace("${{ matrix.platform }}",f"linux/{arch}").replace("${{ matrix.arch }}",arch)
                env={**os.environ,"PATH":f"{root}:"+os.environ["PATH"],"DOCKER_ARGS":str(log),
                    "source_snapshot":"sha256:"+"d"*64,"GITHUB_SHA":"a"*40,
                    "GITHUB_SERVER_URL":"https://github.com","GITHUB_REPOSITORY":"njvenis/volt"}
                result=subprocess.run(["bash","-euc",script],env=env,cwd=ROOT,text=True,capture_output=True)
                self.assertEqual(result.returncode,0,result.stderr)
                expected=subprocess.check_output([sys.executable,str(ROOT/"tools/release/portable_demo.py"),"ce-image","--platform",f"linux/{arch}"],text=True).strip()
                rows=log.read_text().splitlines()
                self.assertEqual(len(rows),2)
                for row in rows:
                    self.assertIn("CE_IMAGE="+expected,row)
                    self.assertIn("--platform linux/"+arch,row)


if __name__ == "__main__":
    unittest.main()
