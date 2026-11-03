import base64, hashlib, json, sys, unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).parents[2] / "tools" / "release"))
import publication_verify as verify

class PublicationVerifierTests(unittest.TestCase):
    def fixture(self, digest="sha256:" + "d" * 64, source="a" * 40):
        subject = [{"name":"ghcr.io/njvenis/volt", "digest":{"sha256":digest.removeprefix("sha256:")}}]
        spdx = {"SPDXID":"SPDXRef-DOCUMENT", "name":"fixture"}
        provenance = {"buildDefinition":{
            "buildType":"https://github.com/Attestations/GitHubActionsWorkflow@v1",
            "externalParameters":{"workflow":{"repository":"https://github.com/njvenis/volt","ref":"njvenis/volt/.github/workflows/release.yml@refs/heads/main"},"source":{"uri":"https://github.com/njvenis/volt","ref":source}},
            "internalParameters":{},"resolvedDependencies":[{"uri":"git+https://github.com/njvenis/volt","digest":{"gitCommit":source}}]},
            "runDetails":{"builder":{"id":"https://github.com/actions/runner"},"metadata":{"invocationId":"https://github.com/njvenis/volt/actions/runs/123"}}}
        spdx_stmt = {"_type":"https://in-toto.io/Statement/v1", "subject":subject, "predicateType":"https://spdx.dev/Document", "predicate":spdx}
        prov_stmt = {"_type":"https://in-toto.io/Statement/v1", "subject":subject, "predicateType":"https://slsa.dev/provenance/v1", "predicate":provenance}
        enc=lambda x: json.dumps({"payload":base64.b64encode(json.dumps(x).encode()).decode()})
        return digest, source, spdx, provenance, enc(spdx_stmt), enc(prov_stmt)

    def test_actual_consumer_commands_verify_signature_identity_and_both_predicates(self):
        with TemporaryDirectory() as temp:
            root=Path(temp); digest,source,spdx,prov,spdx_out,prov_out=self.fixture()
            spdx_path=root/"sbom.json"; spdx_path.write_text(json.dumps(spdx))
            prov_path=root/"provenance.json"; prov_path.write_text(json.dumps(prov))
            notice=root/"notice.json"; notice.write_text(json.dumps({"image_id":"sha256:"+"b"*64,"platform":"linux/amd64","files":[{"path":"sbom.spdx.json","sha256":hashlib.sha256(spdx_path.read_bytes()).hexdigest()}]}))
            calls=[]
            def run(cmd, **kwargs):
                calls.append(cmd)
                if "verify-attestation" not in cmd: return SimpleNamespace(stdout="[]")
                return SimpleNamespace(stdout=spdx_out if "spdxjson" in cmd else prov_out)
            with patch.object(verify.subprocess,"run",side_effect=run):
                verify.verify("cosign",digest,source,"sha256:"+"b"*64,spdx_path,prov_path,notice)
            self.assertEqual(len(calls),3)
            self.assertEqual(calls[0][1:3],["verify","--output=json"])
            for call in calls:
                self.assertIn(verify.IDENTITY,call); self.assertIn(verify.ISSUER,call); self.assertIn("ghcr.io/njvenis/volt@"+digest,call)

    def test_actual_consumer_rejects_wrong_notice_image_and_predicate_subject(self):
        with TemporaryDirectory() as temp:
            root=Path(temp); digest,source,spdx,prov,spdx_out,prov_out=self.fixture()
            spdx_path=root/"sbom.json"; spdx_path.write_text(json.dumps(spdx)); prov_path=root/"prov.json"; prov_path.write_text(json.dumps(prov))
            notice=root/"notice.json"; notice.write_text(json.dumps({"image_id":"sha256:"+"c"*64,"platform":"linux/amd64","files":[{"path":"sbom.spdx.json","sha256":hashlib.sha256(spdx_path.read_bytes()).hexdigest()}]}))
            with patch.object(verify.subprocess,"run") as run:
                with self.assertRaisesRegex(ValueError,"notice manifest"):
                    verify.verify("cosign",digest,source,"sha256:"+"b"*64,spdx_path,prov_path,notice)
                run.assert_not_called()
            notice.write_text(json.dumps({"image_id":"sha256:"+"b"*64,"platform":"linux/amd64","files":[{"path":"sbom.spdx.json","sha256":hashlib.sha256(spdx_path.read_bytes()).hexdigest()}]}))
            _,_,_,_,wrong_spdx,wrong_prov=self.fixture("sha256:"+"e"*64,source)
            def intercepted(cmd, **kwargs):
                if "verify-attestation" not in cmd: return SimpleNamespace(stdout="[]")
                return SimpleNamespace(stdout=wrong_spdx if "spdxjson" in cmd else wrong_prov)
            with patch.object(verify.subprocess,"run",side_effect=intercepted):
                with self.assertRaisesRegex(ValueError,"SPDX attestation"):
                    verify.verify("cosign",digest,source,"sha256:"+"b"*64,spdx_path,prov_path,notice)

    def test_actual_consumer_rejects_contradictory_volt_source_even_with_matching_unrelated_sha(self):
        with TemporaryDirectory() as temp:
            root=Path(temp); digest,source,spdx,prov,spdx_out,_=self.fixture()
            spdx_path=root/"sbom.json"; spdx_path.write_text(json.dumps(spdx))
            prov_path=root/"provenance.json"
            contradictory=json.loads(json.dumps(prov))
            contradictory["buildDefinition"]["externalParameters"]["source"]["ref"]="e"*40
            contradictory["buildDefinition"]["resolvedDependencies"].append({"uri":"git+https://example.invalid/other","digest":{"gitCommit":source}})
            prov_path.write_text(json.dumps(contradictory))
            notice=root/"notice.json"; notice.write_text(json.dumps({"image_id":"sha256:"+"b"*64,"platform":"linux/amd64","files":[{"path":"sbom.spdx.json","sha256":hashlib.sha256(spdx_path.read_bytes()).hexdigest()}]}))
            _,_,_,_,_,bad_prov_out=self.fixture()
            bad_statement={"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"ghcr.io/njvenis/volt","digest":{"sha256":digest.removeprefix("sha256:")}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":contradictory}
            encoded=json.dumps({"payload":base64.b64encode(json.dumps(bad_statement).encode()).decode()})
            def intercepted(cmd, **kwargs):
                if "verify-attestation" not in cmd: return SimpleNamespace(stdout="[]")
                return SimpleNamespace(stdout=spdx_out if "spdxjson" in cmd else encoded)
            with patch.object(verify.subprocess,"run",side_effect=intercepted):
                with self.assertRaisesRegex(ValueError,"source URI/ref"):
                    verify.verify("cosign",digest,source,"sha256:"+"b"*64,spdx_path,prov_path,notice)

    def test_actual_consumer_rejects_wrong_workflow_uri_ref_and_build_type(self):
        with TemporaryDirectory() as temp:
            root=Path(temp); digest,source,spdx,prov,spdx_out,_=self.fixture()
            spdx_path=root/"sbom.json"; spdx_path.write_text(json.dumps(spdx))
            prov_path=root/"provenance.json"; prov_path.write_text(json.dumps(prov))
            notice=root/"notice.json"; notice.write_text(json.dumps({"image_id":"sha256:"+"b"*64,"platform":"linux/amd64","files":[{"path":"sbom.spdx.json","sha256":hashlib.sha256(spdx_path.read_bytes()).hexdigest()}]}))
            variants=[]
            wrong_repo=json.loads(json.dumps(prov)); wrong_repo["buildDefinition"]["externalParameters"]["workflow"]["repository"]="https://example.invalid/volt"; variants.append(wrong_repo)
            wrong_workflow_ref=json.loads(json.dumps(prov)); wrong_workflow_ref["buildDefinition"]["externalParameters"]["workflow"]["ref"]="njvenis/volt/.github/workflows/other.yml@refs/heads/main"; variants.append(wrong_workflow_ref)
            wrong_source_uri=json.loads(json.dumps(prov)); wrong_source_uri["buildDefinition"]["externalParameters"]["source"]["uri"]="https://example.invalid/volt"; variants.append(wrong_source_uri)
            wrong_build=json.loads(json.dumps(prov)); wrong_build["buildDefinition"]["buildType"]="https://example.invalid/build"; variants.append(wrong_build)
            missing_source=json.loads(json.dumps(prov)); del missing_source["buildDefinition"]["externalParameters"]["source"]; variants.append(missing_source)
            for bad in variants:
                statement={"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"ghcr.io/njvenis/volt","digest":{"sha256":digest.removeprefix("sha256:")}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":bad}
                encoded=json.dumps({"payload":base64.b64encode(json.dumps(statement).encode()).decode()})
                def intercepted(cmd, **kwargs):
                    if "verify-attestation" not in cmd: return SimpleNamespace(stdout="[]")
                    return SimpleNamespace(stdout=spdx_out if "spdxjson" in cmd else encoded)
                with patch.object(verify.subprocess,"run",side_effect=intercepted):
                    with self.assertRaisesRegex(ValueError,"exact source commit and registry digest"):
                        verify.verify("cosign",digest,source,"sha256:"+"b"*64,spdx_path,prov_path,notice)

if __name__ == "__main__": unittest.main()
