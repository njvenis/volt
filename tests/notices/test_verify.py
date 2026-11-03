import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import zipfile
import pytest


VERIFY = Path(__file__).resolve().parents[2] / "tools/notices/verify.py"
SPEC = importlib.util.spec_from_file_location("notice_verify", VERIFY)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
COLLECT_SPEC = importlib.util.spec_from_file_location("notice_collect", VERIFY.parents[1] / "notices/collect.py")
COLLECT = importlib.util.module_from_spec(COLLECT_SPEC)
COLLECT_SPEC.loader.exec_module(COLLECT)


def test_sha256_member_parser_requires_complete_unique_digest_size_rows():
    parsed = MODULE.parse_sha256_members(f"{'a' * 64} 12 one.tar.xz\n{'b' * 64} 0 empty.diff")
    assert parsed == {"one.tar.xz": ("a" * 64, 12), "empty.diff": ("b" * 64, 0)}
    for malformed in (
        "", "bad 2 file", f"{'a' * 64} -1 file", f"{'a' * 64} 3 file\n{'b' * 64} 4 file",
        f"{'a' * 64} 3 file\n{'b' * 64} 4 file",
    ):
        try:
            MODULE.parse_sha256_members(malformed)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted malformed signed member list: {malformed!r}")


def test_debian_source_groups_deduplicate_package_license_tokens_and_keep_expression(tmp_path):
    files = [{"path": "usr/share/doc/sample/copyright", "file": "image-files/copyright", "sha256": "a" * 64}]
    packages = [
        {"type": "deb", "name": "sample-bin", "version": "1.0+b1", "metadata": {"source": "sample", "sourceVersion": "1.0"}, "licenses": [{"value": "GPL-3+", "spdxExpression": "GPL-3.0-or-later", "type": "declared", "locations": [{"path": "/usr/share/doc/sample/copyright"}]}]},
        {"type": "deb", "name": "sample-doc", "version": "1.0", "metadata": {"source": "sample", "sourceVersion": "1.0"}, "licenses": [{"value": "GPL-3+", "spdxExpression": "GPL-3.0-or-later", "type": "declared", "locations": [{"path": "/usr/share/doc/sample/copyright"}]}]},
    ]
    groups = COLLECT.debian_source_groups(packages, files, tmp_path)
    assert len(groups) == 1
    assert groups[0]["source_package"] == "sample"
    assert len(groups[0]["binary_packages"]) == 2
    assert groups[0]["license_declarations"][0]["spdx_expression"] == "GPL-3.0-or-later"


def test_license_records_preserve_spdx_or_and_expression():
    expression = "MPL-2.0 AND (Apache-2.0 OR MIT)"
    rows = COLLECT.license_records({"licenses": [{"value": expression, "spdxExpression": expression, "type": "declared"}]})
    assert rows[0]["spdx_expression"] == expression


def test_debian_source_candidates_are_package_version_attributed():
    root = Path("/tmp") / "unused-notices-test-root"
    groups = [{"source_package": "sample", "source_version": "1.0", "binary_packages": [{"name": "sample-bin", "version": "1.0"}], "copyright_files": [{"path": "/usr/share/doc/sample/copyright", "sha256": "a" * 64, "inventory_file": "notices/copyright"}], "license_declarations": [{"value": "GPL-2+", "spdx_expression": "GPL-2.0-or-later", "copyright_path": "/usr/share/doc/sample/copyright", "copyright_sha256": "a" * 64}]}]
    candidates = COLLECT.debian_source_offer_candidates(groups)
    assert len(candidates) == 1
    assert (candidates[0]["source_package"], candidates[0]["source_version"]) == ("sample", "1.0")
    assert candidates[0]["status"] == "pending"


def test_source_candidate_enumerates_exact_dep5_files_stanzas(tmp_path):
    notice = tmp_path / "notices/copyright"
    notice.parent.mkdir()
    notice.write_text("Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n\nFiles: src/*\nCopyright: Example\nLicense: GPL-3+\n\nFiles: debian/*\nCopyright: Example\nLicense: MIT\n")
    groups = [{"source_package": "sample", "source_version": "1.0", "binary_packages": [], "copyright_files": [{"path": "/usr/share/doc/sample/copyright", "sha256": hashlib.sha256(notice.read_bytes()).hexdigest(), "inventory_file": "notices/copyright"}], "license_declarations": [{"spdx_expression": "GPL-3.0-or-later", "copyright_sha256": hashlib.sha256(notice.read_bytes()).hexdigest()}]}]
    candidate = COLLECT.debian_source_offer_candidates(groups, root=tmp_path)[0]
    assert [row["files_patterns"] for row in candidate["file_stanzas"]] == [["src/*"], ["debian/*"]]
    assert all(len(row["stanza_sha256"]) == 64 for row in candidate["file_stanzas"])


def test_collector_relative_inventory_paths_resolve_from_output_root(tmp_path):
    from tempfile import TemporaryDirectory
    output = tmp_path / "out"
    notice = output / "notices/image-files/copyright"
    notice.parent.mkdir(parents=True)
    notice.write_text("Files: src/*\nLicense: GPL-3+\n\nFiles: debian/*\nLicense: MIT\n")
    digest = hashlib.sha256(notice.read_bytes()).hexdigest()
    packages = [{"type": "deb", "name": "sample-bin", "version": "1", "metadata": {"source": "sample", "sourceVersion": "1"},
                 "licenses": [{"value": "GPL-3+", "spdxExpression": "GPL-3.0-or-later", "type": "declared", "locations": [{"path": "/usr/share/doc/sample/copyright"}]}]}]
    image_files = [{"path": "usr/share/doc/sample/copyright", "file": "image-files/copyright", "sha256": digest}]
    groups = COLLECT.debian_source_groups(packages, image_files, output)
    candidates = COLLECT.debian_source_offer_candidates(groups, root=output)
    assert len(candidates) == 1
    assert [x["files_patterns"] for x in candidates[0]["file_stanzas"]] == [["src/*"], ["debian/*"]]
    disposition = {"status": "pending", "source_package": "sample", "source_version": "1"}
    errors = MODULE.validate_source_disposition(candidates[0], disposition, output)
    assert any("pending or stale" in e for e in errors)
    assert not any("does not enumerate every exact copyright Files stanza" in e for e in errors)
    broken_root = COLLECT.debian_source_offer_candidates(groups, root=output / "notices")
    assert broken_root[0]["file_stanzas"] == []
    declaration = broken_root[0]["license_declarations"][0]
    attempted = {"status": "resolved", "source_package": "sample", "source_version": "1", "decision": "excluded",
                 "declaration_resolutions": [{"status": "resolved", "spdx_expression": declaration["spdx_expression"], "copyright_sha256": declaration["copyright_sha256"], "satisfied_license_term": ["GPL-3.0-or-later"], "covered_file_pattern_evidence": ["src/*"], "reviewed_source_file_sha256": "a"*64}], "file_stanza_resolutions": []}
    broken_errors = MODULE.validate_source_disposition(broken_root[0], attempted, output)
    assert any("does not enumerate every exact copyright Files stanza" in e for e in broken_errors)


def test_source_disposition_requires_every_exact_file_stanza(tmp_path):
    notice = tmp_path / "notices/copyright"
    notice.parent.mkdir()
    notice.write_text("Files: *\nLicense: GPL-3+\n")
    copyright_sha = hashlib.sha256(notice.read_bytes()).hexdigest()
    candidate = {"source_package": "sample", "source_version": "1", "copyright_files": [{"path": "/usr/share/doc/sample/copyright", "inventory_file": "notices/copyright", "sha256": copyright_sha}], "file_stanzas": [{"copyright_path": "/usr/share/doc/sample/copyright", "copyright_sha256": copyright_sha, "stanza_sha256": "a" * 64, "files_patterns": ["*"]}], "license_declarations": []}
    errors = MODULE.validate_source_disposition(candidate, {"status": "resolved", "source_package": "sample", "source_version": "1", "decision": "source-bundle", "declaration_resolutions": [], "file_stanza_resolutions": []}, tmp_path)
    assert any("does not enumerate every exact copyright Files stanza" in err for err in errors)
    assert any("no complete exact file-stanza disposition" in err for err in errors)


def test_source_stanza_must_bind_exact_package_version_and_bundle_digest(tmp_path):
    notice = tmp_path / "notices/copyright"
    notice.parent.mkdir()
    notice.write_text("Files: *\nLicense: GPL-3+\n")
    copyright_sha = hashlib.sha256(notice.read_bytes()).hexdigest()
    parsed = COLLECT.copyright_stanzas(notice)[0]
    candidate = {"source_package": "sample", "source_version": "1", "copyright_files": [{"path": "/usr/share/doc/sample/copyright", "inventory_file": "notices/copyright", "sha256": copyright_sha}], "file_stanzas": [{"copyright_path": "/usr/share/doc/sample/copyright", "copyright_sha256": copyright_sha, **parsed}], "license_declarations": []}
    disposition = {"status": "resolved", "source_package": "sample", "source_version": "1", "decision": "source-bundle", "declaration_resolutions": [], "source_bundle": {"source_package": "sample", "source_version": "1", "sha256": "b" * 64}, "file_stanza_resolutions": [{"copyright_path": "/usr/share/doc/sample/copyright", "copyright_sha256": copyright_sha, "stanza_sha256": parsed["stanza_sha256"], "files_patterns": parsed["files_patterns"], "action": "source-bundle", "status": "resolved", "source_package": "other", "source_version": "1", "source_bundle_sha256": "c" * 64}]}
    errors = MODULE.validate_source_disposition(candidate, disposition, tmp_path)
    assert any("file stanza" in err and "unresolved or mismatched" in err for err in errors)


def test_spdx_or_and_terms_keep_alternatives_and_conjunctions():
    assert MODULE.spdx_dnf("MIT OR GPL-3.0-or-later") == [("GPL-3.0-or-later",), ("MIT",)]
    assert MODULE.spdx_dnf("Apache-2.0 AND (MIT OR BSD-3-Clause)") == [
        ("Apache-2.0", "BSD-3-Clause"), ("Apache-2.0", "MIT")]


def test_source_disposition_rejects_pending_stale_and_partial_and():
    candidate = {"source_package": "sample", "source_version": "1", "license_declarations": [
        {"spdx_expression": "Apache-2.0 AND MIT", "copyright_sha256": "a" * 64}]}
    assert "pending or stale" in MODULE.validate_source_disposition(candidate, {"status": "pending"}, Path("."))[0]
    resolved = {"status": "resolved", "source_package": "sample", "source_version": "1", "decision": "excluded",
                "declaration_resolutions": [{"status": "resolved", "spdx_expression": "Apache-2.0 AND MIT", "copyright_sha256": "a" * 64,
                                              "satisfied_license_term": ["Apache-2.0"], "covered_file_pattern_evidence": ["Files: *"],
                                              "reviewed_source_file_sha256": "b" * 64}]}
    assert "unresolved OR/AND" in MODULE.validate_source_disposition(candidate, resolved, Path("."))[0]


def test_pygithub_grant_tracks_captured_later_version_header():
    header = "GNU Lesser General Public License\nversion 3 of the License, or (at your option) any later version."
    assert COLLECT.pygithub_license_expression(header) == "LGPL-3.0-or-later"
    assert COLLECT.pygithub_license_expression("GNU LESSER GENERAL PUBLIC LICENSE version 3") is None


def test_signed_index_bundle_binds_release_index_dsc_and_all_members(tmp_path, monkeypatch):
    import gzip
    source = tmp_path / "source.tar.xz"
    source.write_bytes(b"complete source bytes")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    dsc = tmp_path / "sample_1.dsc"
    dsc.write_text(f"Source: sample\nVersion: 1\nChecksums-Sha256:\n {source_hash} {source.stat().st_size} source.tar.xz\n")
    dsc_hash = hashlib.sha256(dsc.read_bytes()).hexdigest()
    index = tmp_path / "Sources.gz"
    index.write_bytes(gzip.compress(f"Package: sample\nVersion: 1\nChecksums-Sha256:\n {dsc_hash} {dsc.stat().st_size} sample_1.dsc\n {source_hash} {source.stat().st_size} source.tar.xz\n".encode()))
    index_hash = hashlib.sha256(index.read_bytes()).hexdigest()
    inrelease = tmp_path / "InRelease"
    inrelease.write_text(f"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nSHA256:\n {index_hash} {index.stat().st_size} main/source/Sources.gz\n-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----\n")
    keyring = tmp_path / "archive-keyring.gpg"
    keyring.write_bytes(b"test keyring")
    class Result:
        returncode = 0
        stdout = ""
        stderr = "gpgv: using RSA key " + "A" * 40 + "\ngpgv: Good signature"
    monkeypatch.setattr(MODULE.subprocess, "run", lambda *args, **kwargs: Result())
    keyring_hash = hashlib.sha256(keyring.read_bytes()).hexdigest()
    monkeypatch.setattr(MODULE, "INDEX_TRUST_ROOTS", {"fixture": (keyring_hash, ("A" * 40,))})
    bundle = {"signed_dsc_path": dsc.name, "signed_dsc_sha256": dsc_hash,
              "files": [{"path": source.name, "filename": source.name, "sha256": source_hash}],
              "index_authentication": {"trust_route": "signed-repository-index", "trust_root": "fixture", "inrelease_path": inrelease.name,
                  "inrelease_sha256": hashlib.sha256(inrelease.read_bytes()).hexdigest(), "index_path": index.name,
                  "index_sha256": index_hash, "index_size": index.stat().st_size, "index_release_path": "main/source/Sources.gz",
                  "keyring_path": keyring.name, "keyring_sha256": hashlib.sha256(keyring.read_bytes()).hexdigest()}}
    assert MODULE.verify_signed_index_bundle(bundle, tmp_path, "sample", "1") == []
    bundle["index_authentication"]["index_sha256"] = "0" * 64
    errors = MODULE.verify_signed_index_bundle(bundle, tmp_path, "sample", "1")
    assert errors == ["sample@1 signed-index index evidence is missing or corrupt"]


def test_disposition_evidence_relative_paths_resolve_from_json_directory(tmp_path):
    source_root = tmp_path / "evidence-input"
    source_root.mkdir()
    notice = source_root / "offer.txt"
    notice.write_text("retained written offer text")
    digest = hashlib.sha256(notice.read_bytes()).hexdigest()
    output = tmp_path / "inventory"
    output.mkdir()
    disposition = {"written_offer": {"path": "offer.txt", "sha256": digest}}
    COLLECT.copy_disposition_evidence({("sample", "1"): {"decision": "written-offer", **disposition}}, output, source_root)
    copied = output / disposition["written_offer"]["path"]
    assert copied.is_file() and hashlib.sha256(copied.read_bytes()).hexdigest() == digest


def test_export_cleanup_removes_only_recorded_container_and_its_volumes(monkeypatch):
    calls = []
    class Result:
        returncode = 0
        stderr = ""
    def fake_run(args, **kwargs):
        calls.append(args); return Result()
    monkeypatch.setattr(COLLECT.subprocess, "run", fake_run)
    records = []
    COLLECT.remove_owned_export_container("fixture-container", ["fixture-volume"], records)
    assert calls == [["docker", "rm", "--volumes", "fixture-container"]]
    assert records[0]["volume_ids"] == ["fixture-volume"]


def test_export_failure_still_removes_recorded_container_and_volumes(tmp_path, monkeypatch):
    import tarfile
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w"):
        pass
    class Process:
        stdout = io.BytesIO(archive_bytes.getvalue())
        stderr = io.BytesIO(b"export failed")
        def wait(self): return 1
    class Result:
        returncode = 0
        stderr = ""
    calls = []
    def fake_run(args, **kwargs):
        calls.append(args)
        if args[:3] == ["docker", "create", "sha256:"]:
            return ""
        return Result()
    def fake_command(args):
        if args == ["docker", "create", "image"]: return "fixture-container"
        if args == ["docker", "inspect", "fixture-container"]: return json.dumps([{"Mounts": [{"Type": "volume", "Name": "fixture-volume"}]}])
        raise AssertionError(args)
    monkeypatch.setattr(COLLECT, "run", fake_command)
    monkeypatch.setattr(COLLECT.subprocess, "Popen", lambda *a, **k: Process())
    monkeypatch.setattr(COLLECT.subprocess, "run", fake_run)
    records = []
    try:
        COLLECT.extract_notice_files("image", tmp_path, records, tmp_path / "cleanup.json")
        assert False, "expected export failure"
    except RuntimeError as exc:
        assert "docker export failed" in str(exc)
    assert records == [{"container_id": "fixture-container", "volume_ids": ["fixture-volume"],
                        "command": ["docker", "rm", "--volumes", "fixture-container"], "exit_code": 0, "stderr": ""}]
    assert json.loads((tmp_path / "cleanup.json").read_text()) == records


def test_copied_binary_source_hash_follows_symlink_and_records_removal(monkeypatch):
    import tarfile
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w") as archive:
        link = tarfile.TarInfo("usr/lib/libssl.so.3"); link.type = tarfile.SYMTYPE; link.linkname = "libssl.so.3.1"
        archive.addfile(link)
        data = b"pinned-source-bytes"
        target = tarfile.TarInfo("usr/lib/libssl.so.3.1"); target.size = len(data)
        archive.addfile(target, io.BytesIO(data))
    class Process:
        stdout = io.BytesIO(archive_bytes.getvalue())
        stderr = io.BytesIO()
        def wait(self): return 0
    class Result:
        returncode = 0
        stderr = ""
    def fake_command(args):
        if args == ["docker", "create", "source-image"]: return "source-container"
        if args == ["docker", "inspect", "source-container"]: return json.dumps([{"Mounts": []}])
        raise AssertionError(args)
    monkeypatch.setattr(COLLECT, "run", fake_command)
    monkeypatch.setattr(COLLECT.subprocess, "Popen", lambda *a, **k: Process())
    monkeypatch.setattr(COLLECT.subprocess, "run", lambda *a, **k: Result())
    cleanup = []
    result = COLLECT.docker_export_file_hashes("source-image", {"/usr/lib/libssl.so.3": "/opt/valkey/lib/libssl.so.3"}, cleanup)
    assert result["/opt/valkey/lib/libssl.so.3"]["resolved_source_path"] == "/usr/lib/libssl.so.3.1"
    assert result["/opt/valkey/lib/libssl.so.3"]["sha256"] == hashlib.sha256(b"pinned-source-bytes").hexdigest()
    assert cleanup[0]["command"] == ["docker", "rm", "--volumes", "source-container"]


def test_cached_classic_store_resolves_registry_digest_to_local_config_id(monkeypatch):
    registry_digest = "sha256:" + "e" * 64
    local_id = "sha256:" + "f" * 64
    reference = "valkey/valkey:9.1.2-alpine@" + registry_digest
    calls = []
    def fake_run(args, **kwargs):
        calls.append(args)
        if args == ["docker", "image", "inspect", reference]:
            return json.dumps([{"Id": local_id, "Os": "linux", "Architecture": "amd64", "RepoDigests": ["valkey/valkey@" + registry_digest]}])
        raise AssertionError(args)
    monkeypatch.setattr(COLLECT, "run", fake_run)
    info = COLLECT.admit_pinned_source_image(reference, registry_digest)
    assert info["RegistryDigest"] == registry_digest
    assert info["LocalImageId"] == local_id
    assert info["Id"] == local_id
    assert calls == [["docker", "image", "inspect", reference]]


def test_cached_modern_store_admits_index_digest_when_local_id_matches(monkeypatch):
    registry_digest = "sha256:" + "e" * 64
    reference = "valkey/valkey:9.1.2-alpine@" + registry_digest
    monkeypatch.setattr(COLLECT, "run", lambda args, **kwargs: json.dumps([{"Id": registry_digest, "Os": "linux", "Architecture": "amd64", "RepoDigests": ["valkey/valkey@" + registry_digest]}]))
    info = COLLECT.admit_pinned_source_image(reference, registry_digest)
    assert info["RegistryDigest"] == registry_digest
    assert info["LocalImageId"] == registry_digest


def test_fresh_daemon_pulls_exact_platform_then_resolves_full_pinned_reference(monkeypatch):
    registry_digest = "sha256:" + "e" * 64
    local_id = "sha256:" + "f" * 64
    reference = "valkey/valkey:9.1.2-alpine@" + registry_digest
    calls = []
    def fake_run(args, **kwargs):
        calls.append(args)
        if args == ["docker", "image", "inspect", reference] and calls.count(args) == 1:
            raise COLLECT.subprocess.CalledProcessError(1, args)
        if args == ["docker", "pull", "--platform=linux/amd64", reference]: return "pulled"
        if args == ["docker", "image", "inspect", reference]:
            return json.dumps([{"Id": local_id, "Os": "linux", "Architecture": "amd64", "RepoDigests": ["valkey/valkey@" + registry_digest]}])
        raise AssertionError(args)
    monkeypatch.setattr(COLLECT, "run", fake_run)
    info = COLLECT.admit_pinned_source_image(reference, registry_digest)
    assert info["LocalImageId"] == local_id
    assert calls == [["docker", "image", "inspect", reference], ["docker", "pull", "--platform=linux/amd64", reference], ["docker", "image", "inspect", reference]]


@pytest.mark.parametrize("repo_digests,os_name,arch", [
    (["other/repo@sha256:" + "e" * 64], "linux", "amd64"),
    (["valkey/valkey@sha256:" + "0" * 64], "linux", "amd64"),
    (["valkey/valkey@sha256:" + "e" * 64], "linux", "arm64"),
])
def test_source_admission_rejects_wrong_repository_digest_or_platform(monkeypatch, repo_digests, os_name, arch):
    registry_digest = "sha256:" + "e" * 64
    reference = "valkey/valkey:9.1.2-alpine@" + registry_digest
    monkeypatch.setattr(COLLECT, "run", lambda args, **kwargs: json.dumps([{"Id": "sha256:" + "f" * 64, "Os": os_name, "Architecture": arch, "RepoDigests": repo_digests}]))
    with pytest.raises(ValueError):
        COLLECT.admit_pinned_source_image(reference, registry_digest)


def test_source_admission_fails_closed_when_pinned_pull_fails(monkeypatch):
    registry_digest = "sha256:" + "e" * 64
    reference = "valkey/valkey:9.1.2-alpine@" + registry_digest
    def fake_run(args, **kwargs):
        raise COLLECT.subprocess.CalledProcessError(1, args)
    monkeypatch.setattr(COLLECT, "run", fake_run)
    with pytest.raises(COLLECT.subprocess.CalledProcessError):
        COLLECT.admit_pinned_source_image(reference, registry_digest)


def test_source_admission_verifier_binds_registry_digest_to_retained_dockerfile(tmp_path):
    (tmp_path / "notices/reference-sources").mkdir(parents=True)
    registry_digest = "sha256:" + "e" * 64
    local_id = "sha256:" + "f" * 64
    reference = "valkey/valkey:9.1.2-alpine@" + registry_digest
    (tmp_path / "notices/reference-sources/Dockerfile.g7").write_text("ARG VALKEY_IMAGE=" + reference + "\n")
    provenance = {"source_image_id": local_id, "source_distribution_admission": {"reference": reference, "registry_digest": registry_digest, "local_image_id": local_id, "platform": "linux/amd64", "repo_digests": ["valkey/valkey@" + registry_digest]}}
    errors = []
    MODULE.validate_source_image_admission(tmp_path, provenance, errors)
    assert not errors
    provenance["source_distribution_admission"]["local_image_id"] = registry_digest
    errors = []
    MODULE.validate_source_image_admission(tmp_path, provenance, errors)
    assert "pinned source-image admission identities are invalid" in errors


def make_valid_sbom_fixture(root: Path):
    root.mkdir(parents=True, exist_ok=True)
    (root / "notices").mkdir()
    (root / "notices/image-files").mkdir()
    image_id = "sha256:" + "a" * 64
    manifest_digest = "sha256:" + "b" * 64
    purl = "pkg:deb/debian/sample@1.0?arch=amd64&distro=debian-13"
    location = "/usr/share/doc/sample/copyright"
    text = b"Sample license text\n"
    text_file = root / "notices/image-files/copyright"
    text_file.write_bytes(text)
    text_sha = hashlib.sha256(text).hexdigest()
    identity = {"type": "deb", "name": "sample", "version": "1.0", "purl": purl, "locations": [location]}
    native = {"artifacts": [{"name": "sample", "version": "1.0", "type": "deb", "purl": purl,
                             "locations": [{"path": location}], "licenses": [{"value": "MIT", "spdxExpression": "MIT", "locations": [{"path": location}]}]}],
              "source": {"type": "image", "metadata": {"userInput": image_id, "manifestDigest": manifest_digest}},
              "distro": {"id": "debian"}}
    spdx = {"packages": [{"name": "sample", "versionInfo": "1.0", "licenseDeclared": "MIT", "externalRefs": [{"referenceType": "purl", "referenceLocator": purl}]},
                          {"name": "sha256", "versionInfo": "b" * 64, "licenseDeclared": "NOASSERTION", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:oci/sha256@sha256%3A" + "b" * 64 + "?arch=amd64"}]}]}
    (root / "sbom.syft.json").write_text(json.dumps(native))
    (root / "sbom.spdx.json").write_text(json.dumps(spdx))
    (root / "notice-manifest.json").write_text(json.dumps({"package_license_evidence": [{"identity": identity,
        "license_evidence": [{"value": "MIT", "locations": [{"path": location}]}], "metadata_license_texts": []}]}))
    (root / "notices/image-license-files.json").write_text(json.dumps([{"path": location.lstrip("/"), "file": "image-files/copyright", "sha256": text_sha}]))
    (root / "notices/launcher-artifacts.json").write_text("[]")
    (root / "notices/package-license-dispositions.json").write_text("[]")
    (root / "notices/ui-bundled-license-assets.json").write_text(json.dumps({"packages": [], "package_count": 0, "unresolved": []}))
    return image_id, manifest_digest


def test_complete_sbom_coverage_fixture_passes():
    from tempfile import TemporaryDirectory
    with TemporaryDirectory() as td:
        root = Path(td); image_id, _ = make_valid_sbom_fixture(root); errors = []
        MODULE.validate_sbom_pair(root, image_id, errors)
        assert errors == []


def test_exact_python_metadata_classifier_and_license_text_fallback_passes(tmp_path):
    image_id, _ = make_valid_sbom_fixture(tmp_path)
    location = "/opt/volt/venv/lib/python3.14/site-packages/django_ninja-1.6.3.dist-info/METADATA"
    site = "/opt/volt/venv/lib/python3.14/site-packages"
    license_path = site + "/django_ninja-1.6.3.dist-info/licenses/LICENSE.txt"
    for path, data in ((location, b"Name: django-ninja\nVersion: 1.6.3\nClassifier: License :: OSI Approved :: MIT License\n"),
                       (license_path, b"MIT license terms\n")):
        rel = path.lstrip("/"); target = tmp_path / "notices/image-files" / Path(rel).name; target.write_bytes(data)
    files = json.loads((tmp_path / "notices/image-license-files.json").read_text())
    metadata_bytes = b"Name: django-ninja\nVersion: 1.6.3\nClassifier: License :: OSI Approved :: MIT License\n"
    license_bytes = b"MIT license terms\n"
    files.extend([{"path": location.lstrip("/"), "sha256": hashlib.sha256(metadata_bytes).hexdigest()}, {"path": license_path.lstrip("/"), "sha256": hashlib.sha256(license_bytes).hexdigest()}])
    (tmp_path / "notices/image-license-files.json").write_text(json.dumps(files))
    native = json.loads((tmp_path / "sbom.syft.json").read_text()); pkg = native["artifacts"][0]
    pkg.update({"name": "django-ninja", "version": "1.6.3", "type": "python", "purl": "pkg:pypi/django-ninja@1.6.3", "licenses": [], "locations": [{"path": location}]})
    (tmp_path / "sbom.syft.json").write_text(json.dumps(native))
    spdx = json.loads((tmp_path / "sbom.spdx.json").read_text()); spdx["packages"][0].update({"name": "django-ninja", "versionInfo": "1.6.3", "licenseDeclared": "NOASSERTION", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/django-ninja@1.6.3"}]}); (tmp_path / "sbom.spdx.json").write_text(json.dumps(spdx))
    manifest = json.loads((tmp_path / "notice-manifest.json").read_text()); ev = manifest["package_license_evidence"][0]; ev.update({"identity": {"type": "python", "name": "django-ninja", "version": "1.6.3", "purl": "pkg:pypi/django-ninja@1.6.3", "locations": [location]}, "license_evidence": [{"value": "NOASSERTION", "locations": [{"path": location}]}], "metadata_license_hints": [], "metadata_license_classifiers": ["License :: OSI Approved :: MIT License"], "metadata_license_identity": {"name": "django-ninja", "version": "1.6.3", "install_location": site, "metadata_path": location, "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest()}, "metadata_license_texts": [{"path": license_path, "sha256": hashlib.sha256(license_bytes).hexdigest(), "version": "1.6.3", "install_location": site}]}); (tmp_path / "notice-manifest.json").write_text(json.dumps(manifest))
    errors=[]; MODULE.validate_sbom_pair(tmp_path, image_id, errors)
    assert not [e for e in errors if "license expression is unknown" in e or "license text has no package/version/path join" in e], errors


def test_noassertion_placeholder_does_not_count_as_license_resolution(tmp_path):
    image_id, _ = make_valid_sbom_fixture(tmp_path)
    native = json.loads((tmp_path / "sbom.syft.json").read_text()); native["artifacts"][0]["licenses"]=[{"value":"NOASSERTION","spdxExpression":"NOASSERTION","locations":[{"path":"/usr/share/doc/sample/copyright"}]}]; (tmp_path / "sbom.syft.json").write_text(json.dumps(native))
    manifest=json.loads((tmp_path / "notice-manifest.json").read_text()); manifest["package_license_evidence"][0]["license_evidence"]=[{"value":"NOASSERTION","locations":[{"path":"/usr/share/doc/sample/copyright"}]}]; (tmp_path / "notice-manifest.json").write_text(json.dumps(manifest))
    errors=[]; MODULE.validate_sbom_pair(tmp_path,image_id,errors)
    assert "package license expression is unknown: sample@1.0" in errors


def test_unknown_none_and_empty_license_placeholders_fail_closed(tmp_path):
    for placeholder in ("UNKNOWN", "NONE", ""):
        root=tmp_path/str(len(placeholder)); image_id,_=make_valid_sbom_fixture(root)
        native=json.loads((root/"sbom.syft.json").read_text());native["artifacts"][0]["licenses"]=[{"value":placeholder,"spdxExpression":placeholder,"locations":[{"path":"/usr/share/doc/sample/copyright"}]}];(root/"sbom.syft.json").write_text(json.dumps(native))
        manifest=json.loads((root/"notice-manifest.json").read_text());manifest["package_license_evidence"][0]["license_evidence"]=[{"value":placeholder,"locations":[{"path":"/usr/share/doc/sample/copyright"}]}];(root/"notice-manifest.json").write_text(json.dumps(manifest))
        errors=[];MODULE.validate_sbom_pair(root,image_id,errors)
        assert "package license expression is unknown: sample@1.0" in errors


def test_pip_launcher_sources_and_targets_are_independently_hash_bound(tmp_path, monkeypatch):
    import io
    import hashlib
    from unittest.mock import patch
    names={"t32.exe","t64-arm.exe","t64.exe","w32.exe","w64-arm.exe","w64.exe"}
    members={"pip/_vendor/vendor.txt":b"distlib==0.4.2\n", "pip/_vendor/distlib/LICENSE.txt":b"Exact license text\n"}
    members.update({f"pip/_vendor/distlib/{name}":("source-"+name).encode() for name in names})
    archive_buffer=io.BytesIO()
    with zipfile.ZipFile(archive_buffer,"w") as z:
        for name,data in members.items():z.writestr(name,data)
    wheel=archive_buffer.getvalue(); files={}; launcher_manifest={}
    repo_root=COLLECT.ROOT; notice_bytes=(repo_root/"third-party/notices/DISTLIB-LAUNCHER-BSD-2.txt").read_bytes(); source_bytes=b"/*\n"+b"".join(b" * "+line for line in notice_bytes.splitlines(keepends=True))+b" */\n"
    for name in sorted(names):
        path=f"pip/_vendor/distlib/{name}";data=members[path];launcher_manifest[name]={"archive_path":path,"size":len(data),"sha256":hashlib.sha256(data).hexdigest()};files["/usr/local/lib/python3.14/site-packages/"+path]={"path":"usr/local/lib/python3.14/site-packages/"+path,"size":len(data),"sha256":hashlib.sha256(data).hexdigest()}
    vendor_path="/usr/local/lib/python3.14/site-packages/pip/_vendor/vendor.txt";files[vendor_path]={"path":vendor_path.lstrip("/"),"file":"vendor.txt","sha256":hashlib.sha256(members["pip/_vendor/vendor.txt"]).hexdigest()}
    dest=tmp_path/"inventory";dest.mkdir();(dest/"vendor.txt").write_bytes(members["pip/_vendor/vendor.txt"])
    asset=tmp_path/"third-party/notices/DISTLIB-PIP-WHEEL-LICENSE.txt";asset.parent.mkdir(parents=True);asset.write_bytes(members["pip/_vendor/distlib/LICENSE.txt"]);(asset.parent/"DISTLIB-LAUNCHER-BSD-2.txt").write_bytes(notice_bytes)
    rows={"schema":"volt-vendored-launchers/v1","pip_launchers":{"version":"26.2.1","wheel_url":"https://example.invalid/pip.whl","wheel_sha256":hashlib.sha256(wheel).hexdigest(),"wheel_size":len(wheel),"vendor_manifest_archive_path":"pip/_vendor/vendor.txt","vendor_manifest_sha256":hashlib.sha256(members["pip/_vendor/vendor.txt"]).hexdigest(),"vendor_manifest_text":"distlib==0.4.2","license_archive_path":"pip/_vendor/distlib/LICENSE.txt","license_file":asset.name,"license_file_sha256":hashlib.sha256(members["pip/_vendor/distlib/LICENSE.txt"]).hexdigest(),"launcher_files":launcher_manifest,"license_expression":"BSD-2-Clause","copyright":"Vinay Sajip","distlib_launcher_source_url":"https://example.invalid/launcher.c","distlib_launcher_source_sha256":hashlib.sha256(source_bytes).hexdigest(),"vendor_path":vendor_path,"launcher_root":"/usr/local/lib/python3.14/site-packages/pip/_vendor/distlib/","pypi_release_url":"https://example.invalid/json"}}
    (tmp_path/"third-party/notices/VENDORED-LAUNCHERS.json").write_text(json.dumps(rows));monkeypatch.setattr(COLLECT,"ROOT",tmp_path)
    def fetch(*args,**kwargs):return io.BytesIO(source_bytes if "launcher.c" in str(args[0]) else wheel)
    with patch.object(COLLECT.urllib.request,"urlopen",fetch):
        result=COLLECT.verify_pip_launcher_evidence(list(files.values()),[{"name":"pip","version":"26.2.1","metadata_path":"/site/pip-26.2.1.dist-info/METADATA"}],dest)
    assert len(result["content_sha256"])==6
    assert len(result["source_material"])==2
    assert all(hashlib.sha256((dest/row["inventory_file"].removeprefix("notices/")).read_bytes()).hexdigest()==row["sha256"] for row in result["source_material"])
    broken=list(files.values());broken[0]={**broken[0],"sha256":"0"*64}
    with patch.object(COLLECT.urllib.request,"urlopen",fetch):
        try:COLLECT.verify_pip_launcher_evidence(broken,[{"name":"pip","version":"26.2.1"}],dest)
        except ValueError as exc:assert "target differs from exact wheel member" in str(exc)
        else:raise AssertionError("tampered installed PE member accepted")
    with patch.object(COLLECT.urllib.request,"urlopen",fetch):
        try:COLLECT.verify_pip_launcher_evidence(list(files.values()),[{"name":"pip","version":"26.2.0"}],dest)
        except ValueError as exc:assert "exactly one matching installed pip distribution version" in str(exc)
        else:raise AssertionError("wrong installed pip version accepted")
    with patch.object(COLLECT.urllib.request,"urlopen",fetch):
        try:COLLECT.verify_pip_launcher_evidence(list(files.values())[1:],[{"name":"pip","version":"26.2.1"}],dest)
        except ValueError as exc:assert "launcher set differs" in str(exc)
        else:raise AssertionError("missing installed PE member accepted")
    extra=[*files.values(),{"path":"usr/local/lib/python3.14/site-packages/pip/_vendor/distlib/extra.exe","size":1,"sha256":"f"*64}]
    with patch.object(COLLECT.urllib.request,"urlopen",fetch):
        try:COLLECT.verify_pip_launcher_evidence(extra,[{"name":"pip","version":"26.2.1"}],dest)
        except ValueError as exc:assert "launcher set differs" in str(exc)
        else:raise AssertionError("extra installed PE member accepted")


def test_wrong_version_python_license_text_cannot_join_by_name(tmp_path):
    image_id, _ = make_valid_sbom_fixture(tmp_path)
    site="/usr/local/lib/python3.14/site-packages"; meta=site+"/cryptography-50.0.1.dist-info/METADATA"; license_path=site+"/cryptography-50.0.1.dist-info/licenses/LICENSE"
    data=b"License: Apache-2.0\n"; license_data=b"Apache text"
    for path, content in ((meta,data),(license_path,license_data)):
        out=tmp_path/"notices/image-files"/Path(path).name; out.write_bytes(content)
    files=json.loads((tmp_path/"notices/image-license-files.json").read_text()); files.extend([{"path":meta.lstrip("/"),"sha256":hashlib.sha256(data).hexdigest()},{"path":license_path.lstrip("/"),"sha256":hashlib.sha256(license_data).hexdigest()}]);(tmp_path/"notices/image-license-files.json").write_text(json.dumps(files))
    native=json.loads((tmp_path/"sbom.syft.json").read_text()); p=native["artifacts"][0];p.update({"name":"cryptography","version":"46.0.5","type":"python","purl":"pkg:pypi/cryptography@46.0.5","licenses":[],"locations":[{"path":"/opt/uvm/venv/lib/python3.14/site-packages/cryptography"}]});(tmp_path/"sbom.syft.json").write_text(json.dumps(native))
    spdx=json.loads((tmp_path/"sbom.spdx.json").read_text());spdx["packages"][0].update({"name":"cryptography","versionInfo":"46.0.5","licenseDeclared":"NOASSERTION","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:pypi/cryptography@46.0.5"}]});(tmp_path/"sbom.spdx.json").write_text(json.dumps(spdx))
    m=json.loads((tmp_path/"notice-manifest.json").read_text());m["package_license_evidence"][0].update({"identity":{"type":"python","name":"cryptography","version":"46.0.5","purl":"pkg:pypi/cryptography@46.0.5","locations":["/opt/uvm/venv/lib/python3.14/site-packages/cryptography"]},"license_evidence":[],"metadata_license_hints":["Apache-2.0"],"metadata_license_identity":{"name":"cryptography","version":"50.0.1","install_location":site,"metadata_path":meta,"metadata_sha256":hashlib.sha256(data).hexdigest()},"metadata_license_texts":[{"path":license_path,"sha256":hashlib.sha256(license_data).hexdigest(),"version":"50.0.1","install_location":site}]});(tmp_path/"notice-manifest.json").write_text(json.dumps(m))
    errors=[];MODULE.validate_sbom_pair(tmp_path,image_id,errors)
    assert "package license expression is unknown: cryptography@46.0.5" in errors


def test_empty_native_sbom_fails_named_assertion():
    from tempfile import TemporaryDirectory
    with TemporaryDirectory() as td:
        root = Path(td); image_id, _ = make_valid_sbom_fixture(root)
        native = json.loads((root / "sbom.syft.json").read_text()); native["artifacts"] = []
        (root / "sbom.syft.json").write_text(json.dumps(native)); errors = []
        MODULE.validate_sbom_pair(root, image_id, errors)
        assert "Syft SBOM artifacts list is empty or invalid" in errors


def test_changed_image_binding_fails_named_assertion():
    from tempfile import TemporaryDirectory
    with TemporaryDirectory() as td:
        root = Path(td); image_id, _ = make_valid_sbom_fixture(root); errors = []
        MODULE.validate_sbom_pair(root, "sha256:" + "c" * 64, errors)
        assert "Syft SBOM image binding does not match the immutable image ID" in errors


def test_package_set_mismatch_fails_named_assertion():
    from tempfile import TemporaryDirectory
    with TemporaryDirectory() as td:
        root = Path(td); image_id, _ = make_valid_sbom_fixture(root)
        spdx = json.loads((root / "sbom.spdx.json").read_text()); spdx["packages"][0]["externalRefs"][0]["referenceLocator"] = "pkg:deb/debian/other@1.0"
        (root / "sbom.spdx.json").write_text(json.dumps(spdx)); errors = []
        MODULE.validate_sbom_pair(root, image_id, errors)
        assert "Syft and SPDX package identity/version/location sets differ" in errors


def test_noassertion_without_exact_text_join_fails_named_assertion():
    from tempfile import TemporaryDirectory
    with TemporaryDirectory() as td:
        root = Path(td); image_id, _ = make_valid_sbom_fixture(root)
        spdx = json.loads((root / "sbom.spdx.json").read_text()); spdx["packages"][0]["licenseDeclared"] = "NOASSERTION"
        (root / "sbom.spdx.json").write_text(json.dumps(spdx))
        manifest = json.loads((root / "notice-manifest.json").read_text()); manifest["package_license_evidence"] = []
        (root / "notice-manifest.json").write_text(json.dumps(manifest)); errors = []
        MODULE.validate_sbom_pair(root, image_id, errors)
        assert "SPDX NOASSERTION lacks joined license/text evidence: sample@1.0" in errors


def test_expired_written_offer_is_rejected(tmp_path):
    import datetime
    candidate = {"source_package": "sample", "source_version": "1", "license_declarations": [
        {"spdx_expression": "GPL-3.0-or-later", "copyright_sha256": "a" * 64}]}
    evidence = tmp_path / "offer.txt"; evidence.write_text("written offer")
    disposition = {"status": "resolved", "source_package": "sample", "source_version": "1", "decision": "written-offer",
                   "declaration_resolutions": [{"status": "resolved", "spdx_expression": "GPL-3.0-or-later", "copyright_sha256": "a" * 64}],
                   "written_offer": {"path": "offer.txt", "sha256": hashlib.sha256(b"written offer").hexdigest(), "scope": "sample source", "validity": "expires", "valid_until": (datetime.date.today() - datetime.timedelta(days=1)).isoformat()}}
    assert any("written offer is expired" in err for err in MODULE.validate_source_disposition(candidate, disposition, tmp_path))


def test_complete_notice_inventory_verifier_fixture_passes(tmp_path, monkeypatch, capsys):
    import hashlib
    image_id = "sha256:" + "a" * 64
    source_id = "sha256:" + "d" * 64
    source_registry_digest = "sha256:" + "c" * 64
    source_reference = "valkey/valkey:9.1.2-alpine@" + source_registry_digest
    manifest_digest = "sha256:" + "b" * 64
    purl = "pkg:deb/debian/sample@1.0?arch=amd64&distro=debian-13"
    location = "/usr/share/doc/sample/copyright"
    (tmp_path / "notices/image-files").mkdir(parents=True)
    (tmp_path / "notices").mkdir(exist_ok=True)
    (tmp_path / "notices/image-files/copyright").write_bytes(b"Sample license text\n")
    copied_paths = ["/opt/valkey/bin/valkey-server", "/opt/valkey/bin/valkey-cli", "/opt/valkey/lib/ld-musl-x86_64.so.1", "/opt/valkey/lib/libc.musl-x86_64.so.1", "/opt/valkey/lib/libssl.so.3", "/opt/valkey/lib/libcrypto.so.3"]
    copied_rows, source_files, image_files = [], {}, [{"path": location.lstrip("/"), "file": "image-files/copyright", "sha256": hashlib.sha256(b"Sample license text\n").hexdigest(), "kind": "license-or-copyright"}]
    for index, path in enumerate(copied_paths):
        data = f"runtime-{index}".encode(); digest = hashlib.sha256(data).hexdigest(); rel = path.lstrip("/")
        copied_rows.append({"path": path, "sha256": digest, "size": len(data), "source_package": "fixture"})
        source_files[path] = {"source_path": "/fixture/" + str(index), "resolved_source_path": "/fixture/" + str(index), "sha256": digest, "size": len(data)}
        image_files.append({"path": rel, "sha256": digest, "size": len(data), "kind": "copied-runtime-binary"})
    identity = {"type": "deb", "name": "sample", "version": "1.0", "purl": purl, "locations": [location]}
    artifact = {"name": "sample", "version": "1.0", "type": "deb", "purl": purl, "locations": [{"path": location}], "licenses": [{"value": "MIT", "spdxExpression": "MIT", "locations": [{"path": location}]}]}
    (tmp_path / "sbom.syft.json").write_text(json.dumps({"artifacts": [artifact], "source": {"type": "image", "metadata": {"userInput": image_id, "manifestDigest": manifest_digest}}, "distro": {"id": "debian"}}))
    (tmp_path / "sbom.spdx.json").write_text(json.dumps({"packages": [{"name": "sample", "versionInfo": "1.0", "licenseDeclared": "MIT", "externalRefs": [{"referenceType": "purl", "referenceLocator": purl}]}, {"name": "sha256", "versionInfo": "b" * 64, "licenseDeclared": "NOASSERTION", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:oci/sha256@sha256%3A" + "b" * 64 + "?arch=amd64"}]}]}))
    (tmp_path / "sbom.valkey-source.syft.json").write_text(json.dumps({"artifacts": [{"name": "valkey", "version": "9.1.2"}], "source": {"type": "image", "metadata": {"userInput": source_id}}}))
    artifact_rows = []
    for rel, data in {
        "notices/VOLT-THIRD-PARTY-NOTICES.md": b"notices", "notices/VOLT-LICENSE.txt": b"license",
        "notices/OPENSSL-APACHE-2.0.txt": b"openssl", "notices/DISTLIB-LAUNCHER-BSD-2.txt": b"distlib",
        "notices/SETUPTOOLS-84.0.0-MIT-LICENSE.txt": b"setuptools", "notices/MUSL-1.2.6-COPYRIGHT": b"musl",
        "notices/MUSL-LICENSE-EVIDENCE.json": b"{}", "notices/embedded-notice-assets.json": b"[]",
        "notices/image-license-files.json": json.dumps(image_files).encode(), "notices/python-distribution-license-evidence.json": b"{}",
        "notices/copied-source-file-hashes.json": json.dumps(source_files).encode(), "notices/docker-cleanup-records.json": json.dumps([{"container_id": "cid", "volume_ids": [], "command": ["docker", "rm", "--volumes", "cid"], "exit_code": 0}]).encode(),
        "notices/ui-production-lock-licenses.json": b"[]", "notices/ui-bundled-license-assets.json": b'{"packages":[],"package_count":0,"unresolved":[]}',
        "notices/debian-source-packages.json": b"[]", "notices/debian-source-candidates.json": b"[]",
        "notices/launcher-artifacts.json": b"[]", "notices/package-license-dispositions.json": b"[]",
    }.items():
        target = tmp_path / rel; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
        artifact_rows.append({"path": rel, "sha256": hashlib.sha256(data).hexdigest()})
    source_files_json = tmp_path / "notices/copied-source-file-hashes.json"
    (tmp_path / "notices/reference-sources").mkdir(parents=True, exist_ok=True)
    retained_dockerfile = tmp_path / "notices/reference-sources/Dockerfile.g7"
    retained_dockerfile.write_text("ARG VALKEY_IMAGE=" + source_reference + "\n")
    provenance = {"source_image_id": source_id, "source_image_platform": "linux/amd64", "source_image_package_evidence": {}, "copied_assets": copied_rows, "missing_assets": [], "source_files": source_files,
                  "source_distribution_admission": {"reference": source_reference, "registry_digest": source_registry_digest, "local_image_id": source_id, "platform": "linux/amd64", "repo_digests": ["valkey/valkey@" + source_registry_digest]}}
    (tmp_path / "notices/copied-binary-provenance.json").write_text(json.dumps(provenance))
    artifact_rows.append({"path": "notices/copied-binary-provenance.json", "sha256": hashlib.sha256((tmp_path / "notices/copied-binary-provenance.json").read_bytes()).hexdigest()})
    artifact_rows.append({"path": "notices/reference-sources/Dockerfile.g7", "sha256": hashlib.sha256(retained_dockerfile.read_bytes()).hexdigest()})
    package_evidence = {"identity": identity, "license_evidence": [{"value": "MIT", "locations": [{"path": location}]}], "metadata_license_texts": []}
    manifest = {"schema": "volt-notice-inventory/v1", "image_id": image_id, "platform": "linux/amd64", "package_count": 1, "packages_with_license_metadata": 1,
                "runtime_ui_packages": 0, "debian_source_candidate_count": 0, "embedded_notice_asset_count": 0, "package_license_evidence": [package_evidence], "unresolved": [], "files": []}
    (tmp_path / "notice-manifest.json").write_text(json.dumps(manifest))
    artifact_rows.extend([{"path": "sbom.syft.json", "sha256": hashlib.sha256((tmp_path / "sbom.syft.json").read_bytes()).hexdigest()}, {"path": "sbom.spdx.json", "sha256": hashlib.sha256((tmp_path / "sbom.spdx.json").read_bytes()).hexdigest()}, {"path": "sbom.valkey-source.syft.json", "sha256": hashlib.sha256((tmp_path / "sbom.valkey-source.syft.json").read_bytes()).hexdigest()}])
    artifact_rows.append({"path": "notices/image-files/copyright", "sha256": hashlib.sha256(b"Sample license text\n").hexdigest()})
    manifest["files"] = artifact_rows
    (tmp_path / "notice-manifest.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(sys, "argv", [str(VERIFY), "--directory", str(tmp_path), "--image", image_id])
    assert MODULE.main() == 0
    assert "PASS: 1 image packages" in capsys.readouterr().out


def test_verify_rejects_corrupt_manifest_artifact(tmp_path, monkeypatch, capsys):
    (tmp_path / "sbom.syft.json").write_text("{}")
    artifact = tmp_path / "sbom.syft.json"
    manifest = {
        "schema": "volt-notice-inventory/v1",
        "image_id": "sha256:" + "a" * 64,
        "platform": "linux/amd64",
        "package_count": 0,
        "packages_with_license_metadata": 0,
        "unresolved": [],
        "files": [{"path": artifact.name, "sha256": hashlib.sha256(b"tampered").hexdigest()}],
    }
    (tmp_path / "notice-manifest.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(sys, "argv", [str(VERIFY), "--directory", str(tmp_path)])
    assert MODULE.main() != 0
    assert "artifact digest mismatch: sbom.syft.json" in capsys.readouterr().err


def test_verify_rejects_unknown_license_finding(tmp_path, monkeypatch, capsys):
    (tmp_path / "notice-manifest.json").write_text(json.dumps({
        "schema": "volt-notice-inventory/v1",
        "image_id": "sha256:" + "a" * 64,
        "platform": "linux/amd64",
        "package_count": 1,
        "packages_with_license_metadata": 0,
        "unresolved": [{"name": "unknown", "reason": "no license"}],
        "files": [],
    }))
    monkeypatch.setattr(sys, "argv", [str(VERIFY), "--directory", str(tmp_path)])
    assert MODULE.main() != 0
    assert "1 unresolved license findings" in capsys.readouterr().err


def test_verify_rejects_missing_notice_files(tmp_path, monkeypatch, capsys):
    (tmp_path / "notice-manifest.json").write_text(json.dumps({
        "schema": "volt-notice-inventory/v1",
        "image_id": "sha256:" + "a" * 64,
        "platform": "linux/amd64",
        "package_count": 0,
        "packages_with_license_metadata": 0,
        "unresolved": [],
        "files": [],
    }))
    monkeypatch.setattr(sys, "argv", [str(VERIFY), "--directory", str(tmp_path)])
    assert MODULE.main() != 0
    assert "required artifact missing: notices/OPENSSL-APACHE-2.0.txt" in capsys.readouterr().err


def test_verify_rejects_missing_copied_binary_coverage(tmp_path, monkeypatch, capsys):
    required = ["sbom.syft.json", "sbom.spdx.json", "notices/VOLT-THIRD-PARTY-NOTICES.md", "notices/VOLT-LICENSE.txt", "notices/image-license-files.json", "notices/copied-binary-provenance.json", "notices/ui-production-lock-licenses.json"]
    for rel in required:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if rel.endswith("copied-binary-provenance.json"):
            path.write_text(json.dumps({"copied_assets": []}))
        elif rel.endswith("ui-production-lock-licenses.json") or rel.endswith("image-license-files.json"):
            path.write_text("[]")
        else:
            path.write_text("test")
    files = [{"path": rel, "sha256": hashlib.sha256((tmp_path / rel).read_bytes()).hexdigest()} for rel in required]
    (tmp_path / "notice-manifest.json").write_text(json.dumps({
        "schema": "volt-notice-inventory/v1",
        "image_id": "sha256:" + "a" * 64,
        "platform": "linux/amd64",
        "package_count": 0,
        "packages_with_license_metadata": 0,
        "unresolved": [],
        "files": files,
    }))
    monkeypatch.setattr(sys, "argv", [str(VERIFY), "--directory", str(tmp_path)])
    assert MODULE.main() != 0
    assert "copied-binary provenance coverage is incomplete" in capsys.readouterr().err


def test_native_python_grant_does_not_replace_exact_licence_text(tmp_path):
    test_exact_python_metadata_classifier_and_license_text_fallback_passes(tmp_path)
    native_path = tmp_path / "sbom.syft.json"
    native = json.loads(native_path.read_text())
    package = native["artifacts"][0]
    metadata_path = package["locations"][0]["path"]
    package["licenses"] = [{"value": "MIT", "locations": [{"path": metadata_path}]}]
    native_path.write_text(json.dumps(native))
    manifest_path = tmp_path / "notice-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    evidence = manifest["package_license_evidence"][0]
    evidence["license_evidence"] = package["licenses"]
    metadata = evidence["metadata_license_identity"]
    declaration_only = {"path": metadata["metadata_path"], "sha256": metadata["metadata_sha256"],
                        "version": metadata["version"], "install_location": metadata["install_location"]}
    for texts in ([], [{**evidence["metadata_license_texts"][0], "version": "99.0"}], [declaration_only]):
        evidence["metadata_license_texts"] = texts
        manifest_path.write_text(json.dumps(manifest))
        errors = []
        MODULE.validate_sbom_pair(tmp_path, "sha256:" + "a" * 64, errors)
        assert "package license text has no package/version/path join: django-ninja@1.6.3" in errors


def test_verifier_rejoins_pip_target_to_retained_wheel(tmp_path, monkeypatch):
    source = b"MZ retained source launcher"
    source_hash = hashlib.sha256(source).hexdigest()
    member = "pip/_vendor/distlib/t64.exe"
    target_path = "/site/pip/_vendor/distlib/t64.exe"
    notices = tmp_path / "notices"
    notices.mkdir()
    wheel = notices / "pip.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(member, source)
    pinned = {"wheel_url": "https://example.invalid/pip.whl", "wheel_size": wheel.stat().st_size,
              "wheel_sha256": MODULE.sha(wheel), "launcher_root": "/site/pip/_vendor/distlib/",
              "launcher_files": {"t64.exe": {"archive_path": member, "size": len(source), "sha256": source_hash}}}
    pin_path = tmp_path / "third-party/notices/VENDORED-LAUNCHERS.json"
    pin_path.parent.mkdir(parents=True)
    pin_path.write_text(json.dumps({"pip_launchers": pinned}))
    monkeypatch.setattr(MODULE, "__file__", str(tmp_path / "tools/notices/verify.py"))
    target = notices / "t64.exe"
    target.write_bytes(source)
    image = {"path": target_path.lstrip("/"), "size": len(source), "sha256": source_hash}
    launcher = {"path": target_path, "sha256": source_hash, "inventory_file": "notices/t64.exe"}
    entry = {"path": target_path, "sha256": source_hash, "size": len(source), "source_archive_path": member,
             "source_sha256": source_hash, "source_size": len(source)}
    disposition = {"source_material": [{"path": pinned["wheel_url"], "inventory_file": "notices/pip.whl"}], "content_sha256": [entry]}
    def verify():
        (notices / "image-license-files.json").write_text(json.dumps([image]))
        (notices / "launcher-artifacts.json").write_text(json.dumps([launcher]))
        errors = []
        MODULE.validate_pip_launcher_binding(tmp_path, disposition, errors)
        return errors
    assert verify() == []
    changed = b"MZ altered target"
    changed_hash = hashlib.sha256(changed).hexdigest()
    target.write_bytes(changed)
    image.update(sha256=changed_hash, size=len(changed))
    launcher["sha256"] = changed_hash
    entry.update(sha256=changed_hash, size=len(changed))
    assert any("target differs from retained source wheel" in error for error in verify())
    # Even changing the recorded source digest cannot rewrite the pinned wheel.
    entry.update(source_sha256=changed_hash, source_size=len(changed))
    assert verify()


def test_export_retains_hyphenated_and_suffixed_licence_names(tmp_path, monkeypatch):
    import tarfile
    archive_bytes = io.BytesIO()
    paths = ["usr/local/lib/python3.14/site-packages/example-1.dist-info/" + name
             for name in ("LICENSE-APACHE", "COPYING-MIT", "mit.LICENSE", "LICENSE.txt")]
    with tarfile.open(fileobj=archive_bytes, mode="w") as archive:
        for path in paths:
            member = tarfile.TarInfo(path)
            member.size = len(b"licence terms")
            archive.addfile(member, io.BytesIO(b"licence terms"))
    class Process:
        stdout = io.BytesIO(archive_bytes.getvalue())
        stderr = io.BytesIO()
        def wait(self): return 0
    def command(args):
        if args == ["docker", "create", "image"]:
            return "fixture-container"
        if args == ["docker", "inspect", "fixture-container"]:
            return json.dumps([{"Mounts": []}])
        raise AssertionError(args)
    monkeypatch.setattr(COLLECT, "run", command)
    monkeypatch.setattr(COLLECT.subprocess, "Popen", lambda *a, **k: Process())
    removed = []
    monkeypatch.setattr(COLLECT, "remove_owned_export_container", lambda cid, *args: removed.append(cid))
    records = COLLECT.extract_notice_files("image", tmp_path)
    assert {row["path"] for row in records} == set(paths)
    assert all((tmp_path / row["file"]).read_bytes() == b"licence terms" for row in records)
    assert removed == ["fixture-container"]


def test_supplemental_licence_replays_exact_source_and_rejects_changes(tmp_path, monkeypatch):
    import tarfile
    text = b"Copyright fixture authors\nMIT licence fixture\n"
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w:gz") as archive:
        member = tarfile.TarInfo("sample-1.0/mit.LICENSE")
        member.size = len(text)
        archive.addfile(member, io.BytesIO(text))
    raw = archive_bytes.getvalue()
    asset = tmp_path / "third-party/notices/sample-MIT.txt"
    asset.parent.mkdir(parents=True)
    asset.write_bytes(text)
    pins = [{"package": "sample", "version": "1.0", "source_url": "https://example.invalid/source.tar.gz",
             "source_size": len(raw), "source_sha256": hashlib.sha256(raw).hexdigest(), "source_member": "sample-1.0/mit.LICENSE",
             "license_file": asset.name, "license_sha256": hashlib.sha256(text).hexdigest(), "license_expression": "MIT", "copyright": "fixture authors"}]
    (asset.parent / "PYTHON-SUPPLEMENTAL-LICENSES.json").write_text(json.dumps(pins))
    monkeypatch.setattr(COLLECT, "ROOT", tmp_path)
    monkeypatch.setattr(COLLECT.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(raw))
    monkeypatch.setattr(MODULE, "__file__", str(tmp_path / "tools/notices/verify.py"))
    notices = tmp_path / "notices"
    notices.mkdir()
    metadata = [{"name": "sample", "version": "1.0", "metadata_sha256": "a" * 64}]
    rows = COLLECT.supplemental_python_licenses(metadata, notices)
    errors = []
    MODULE.validate_supplemental_python_license(tmp_path, rows[0], errors)
    assert errors == []
    assert COLLECT.supplemental_python_licenses([{**metadata[0], "version": "2.0"}], notices) == []
    (notices / asset.name).write_bytes(b"wrong text")
    errors = []
    MODULE.validate_supplemental_python_license(tmp_path, rows[0], errors)
    assert any("text or grant mismatch" in error for error in errors)
    # A changed source archive cannot be admitted by updating ordinary inventory hashes.
    (notices / asset.name).write_bytes(text)
    (tmp_path / rows[0]["source_material"][0]["inventory_file"]).write_bytes(b"wrong archive")
    errors = []
    MODULE.validate_supplemental_python_license(tmp_path, rows[0], errors)
    assert any("source digest mismatch" in error for error in errors)


def test_full_verifier_requires_pip_source_disposition_when_targets_exist(tmp_path, monkeypatch, capsys):
    test_complete_notice_inventory_verifier_fixture_passes(tmp_path, monkeypatch, capsys)
    image_path = tmp_path / "notices/image-license-files.json"
    rows = json.loads(image_path.read_text())
    rows.append({"path": "usr/local/lib/python3.14/site-packages/pip/_vendor/distlib/t64.exe", "sha256": "f" * 64})
    image_path.write_text(json.dumps(rows))
    manifest_path = tmp_path / "notice-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    dispositions_path = tmp_path / "notices/package-license-dispositions.json"
    for dispositions in ([], [{"package": "pip launcher attribution", "version": "distlib 0.4.2 via pip 26.2.1"}],
                         [{"package": "pip vendored distlib Windows launchers", "version": "wrong-version"}]):
        dispositions_path.write_text(json.dumps(dispositions))
        for row in manifest["files"]:
            row["sha256"] = MODULE.sha(tmp_path / row["path"])
        manifest_path.write_text(json.dumps(manifest))
        assert MODULE.main() == 1
        assert "captured pip launchers require exactly one matching versioned source disposition" in capsys.readouterr().err
