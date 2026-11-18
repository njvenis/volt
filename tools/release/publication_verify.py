#!/usr/bin/env python3
"""Verify an already-published RC image and its exact signed attestations."""
from __future__ import annotations
import argparse, base64, hashlib, json, re, subprocess, sys
from pathlib import Path
import provenance as provenance_validator
IDENTITY = "https://github.com/njvenis/volt/.github/workflows/release.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
REPO = "ghcr.io/njvenis/volt"

def statement_rows(raw: str) -> list[dict]:
    data = json.loads(raw)
    if isinstance(data, dict): data = [data]
    if not isinstance(data, list): raise ValueError("Cosign attestation output must be a JSON list")
    rows = []
    for item in data:
        if not isinstance(item, dict) or not isinstance(item.get("payload"), str): raise ValueError("Cosign did not return a verified DSSE payload")
        statement = json.loads(base64.b64decode(item["payload"], validate=True))
        if not isinstance(statement, dict): raise ValueError("attestation payload is not an in-toto statement")
        rows.append(statement)
    return rows

def verify(cosign: str, digest: str, source: str, image_id: str, spdx: Path, provenance: Path,
           notice_manifest: Path, controller_commit: str | None = None, *,
           version: str = "0.1.0-rc.2", platform: str = "linux/amd64") -> None:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) or not re.fullmatch(r"[0-9a-f]{40}", source): raise ValueError("immutable registry digest or source commit is malformed")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id): raise ValueError("image config ID is malformed")
    notice = json.loads(notice_manifest.read_text())
    if version not in {"0.1.0-rc.2", "0.1.0-rc.3"} or platform not in {"linux/amd64", "linux/arm64"}:
        raise ValueError("publication verification version/platform is not explicitly admitted")
    if version == "0.1.0-rc.2" and platform != "linux/amd64":
        raise ValueError("RC2 publication verification remains amd64-only")
    if notice.get("image_id") != image_id or notice.get("platform") != platform: raise ValueError("notice manifest does not match the exact image config ID/platform")
    sbom_hash = hashlib.sha256(spdx.read_bytes()).hexdigest()
    notice_files = notice.get("files")
    if not isinstance(notice_files, list) or not any(isinstance(row, dict) and row.get("path") == "sbom.spdx.json" and row.get("sha256") == sbom_hash for row in notice_files):
        raise ValueError("SPDX SBOM digest is not present in the verified notice inventory")
    ref = f"{REPO}@{digest}"
    identity = ("https://github.com/njvenis/volt/.github/workflows/release-rc3.yml@refs/heads/main"
                if version == "0.1.0-rc.3" else IDENTITY)
    workflow_ref = identity.removeprefix("https://github.com/")
    subprocess.run([cosign, "verify", "--output=json", "--certificate-identity", identity, "--certificate-oidc-issuer", ISSUER, ref], check=True, text=True, capture_output=True)
    def attest(predicate_type):
        return statement_rows(subprocess.run([cosign, "verify-attestation", "--output=json", "--type", predicate_type, "--certificate-identity", identity, "--certificate-oidc-issuer", ISSUER, ref], check=True, text=True, capture_output=True).stdout)
    spdx_rows = attest("spdxjson")
    prov_rows = attest("slsaprovenance1")
    wanted = digest.removeprefix("sha256:")
    def subject_matches(statement):
        subjects = statement.get("subject")
        return isinstance(subjects, list) and any(isinstance(x, dict) and isinstance(x.get("digest"), dict) and x["digest"].get("sha256") == wanted for x in subjects)
    expected_spdx = json.loads(spdx.read_text())
    if not any(subject_matches(row) and row.get("predicateType") == "https://spdx.dev/Document" and row.get("predicate") == expected_spdx for row in spdx_rows):
        raise ValueError("verified SPDX attestation does not match the release SBOM and registry digest")
    expected_prov = json.loads(provenance.read_text())
    provenance_validator.validate(expected_prov, source, expected_controller_commit=controller_commit,
                                  expected_workflow_ref=workflow_ref)
    def provenance_matches(row: dict) -> bool:
        predicate = row.get("predicate")
        if not isinstance(predicate, dict): return False
        try:
            provenance_validator.validate(predicate, source, expected_controller_commit=controller_commit,
                                           expected_workflow_ref=workflow_ref)
        except ValueError:
            return False
        return subject_matches(row) and row.get("predicateType") == "https://slsa.dev/provenance/v1" and predicate == expected_prov
    if not any(provenance_matches(row) for row in prov_rows):
        raise ValueError("verified provenance attestation does not match the exact source commit and registry digest")

def verify_index(cosign: str, digest: str, source: str, controller: str, index: Path, provenance: Path) -> None:
    import registry
    raw = index.read_bytes()
    if "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("index content digest differs")
    predicate = json.loads(provenance.read_text())
    provenance_validator.validate(predicate, source, expected_controller_commit=controller,
        expected_workflow_ref=provenance_validator.RC3_WORKFLOW_REF)
    deps = predicate["buildDefinition"]["resolvedDependencies"]
    children = {}
    for arch in ("amd64", "arm64"):
        uri = f"pkg:docker/ghcr.io/njvenis/volt?platform=linux/{arch}"
        matching = [row for row in deps if row.get("uri") == uri]
        if len(matching) != 1:
            raise ValueError("index provenance must bind exactly one child per architecture")
        children[arch] = "sha256:" + matching[0]["digest"]["sha256"]
    registry.validate_index(json.loads(raw), children["amd64"], children["arm64"])
    identity = "https://github.com/" + provenance_validator.RC3_WORKFLOW_REF
    flags = ["--certificate-identity", identity, "--certificate-oidc-issuer", ISSUER]
    subprocess.run([cosign,"verify","--output=json",*flags,f"{REPO}@{digest}"], check=True, capture_output=True, text=True)
    rows = statement_rows(subprocess.run([cosign,"verify-attestation","--output=json","--type","slsaprovenance1",
        *flags,f"{REPO}@{digest}"],check=True,capture_output=True,text=True).stdout)
    if not any(row.get("predicateType") == "https://slsa.dev/provenance/v1" and row.get("predicate") == predicate
        and any(x.get("digest",{}).get("sha256") == digest.removeprefix("sha256:") for x in row.get("subject",[])) for row in rows):
        raise ValueError("index provenance signature/subject does not bind exact children")


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("--cosign",required=True); p.add_argument("--digest",required=True)
    p.add_argument("--source",required=True); p.add_argument("--image-id")
    p.add_argument("--spdx",type=Path); p.add_argument("--provenance",type=Path,required=True)
    p.add_argument("--notice-manifest",type=Path); p.add_argument("--controller-commit")
    p.add_argument("--verify-index",type=Path)
    p.add_argument("--version",choices=("0.1.0-rc.2","0.1.0-rc.3"),default="0.1.0-rc.2")
    p.add_argument("--platform",choices=("linux/amd64","linux/arm64"),default="linux/amd64")
    a=p.parse_args()
    try:
        if a.verify_index:
            verify_index(a.cosign,a.digest,a.source,a.controller_commit,a.verify_index,a.provenance)
        else:
            if not all((a.image_id,a.spdx,a.notice_manifest)):
                raise ValueError("child verification requires image ID, SPDX and notice manifest")
            verify(a.cosign,a.digest,a.source,a.image_id,a.spdx,a.provenance,a.notice_manifest,a.controller_commit,
                   version=a.version,platform=a.platform)
        print(f"verified registry signature and exact attestations for {REPO}@{a.digest}")
        return 0
    except (OSError,ValueError,KeyError,TypeError,subprocess.CalledProcessError,json.JSONDecodeError) as exc:
        print(f"publication verification failed: {exc}",file=sys.stderr)
        return 2

if __name__ == "__main__": raise SystemExit(main())
