#!/usr/bin/env python3
"""Verify image binding, inventory coverage and artifact integrity."""
from __future__ import annotations

import argparse
import hashlib
import json
import gzip
import lzma
import zipfile
import tarfile
from email.parser import Parser
from datetime import date
from pathlib import Path
import re
import subprocess
import sys
from collections import Counter

IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
DEBIAN_DEVELOPER_KEYRING_SHA256 = "81e08f47b0dd8a563a2742ad90878ccefe53aa0728b095acbea3efda84381ea9"
INDEX_TRUST_ROOTS = {
    "debian-trixie-archive": ("506b815cbb32d9b6066b4a2aa524071e071761e7e7f68c3ac74f3061ba852017", ("B8E5F13176D2A7A75220028078DBA3BC47EF2265", "41587F7DB8C774BCCF131416762F67A0B2C39DE4")),
    "postgresql-pgdg": ("8ca1b2fb3a2533cc44b87ee146a03858f6e8ea31c1f165dfd38dc270c04ada0f", ("B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8",)),
}


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def parse_dsc_control(path: Path):
    text = path.read_text(errors="replace")
    if text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        text = text.split("\n\n", 1)[1].split("\n-----BEGIN PGP SIGNATURE-----", 1)[0]
    return Parser().parsestr(text)


def parse_deb822_index(path: Path):
    raw = path.read_bytes()
    if path.suffix == ".gz":
        raw = gzip.decompress(raw)
    elif path.suffix == ".xz":
        raw = lzma.decompress(raw)
    return [Parser().parsestr(block) for block in raw.decode(errors="replace").split("\n\n") if block.strip()]


def parse_sha256_members(value: str) -> dict[str, tuple[str, int]]:
    """Parse a complete, unique Debian Checksums-Sha256 field."""
    members = {}
    for line in value.splitlines():
        parts = line.split()
        if len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]) or not parts[1].isdigit() or not parts[2]:
            raise ValueError("malformed SHA-256 member row")
        if parts[2] in members:
            raise ValueError("duplicate SHA-256 member filename")
        members[parts[2]] = (parts[0], int(parts[1]))
    if not members:
        raise ValueError("empty SHA-256 member list")
    return members


def verify_signed_index_bundle(bundle: dict, root: Path, package: str, version: str) -> list[str]:
    """Verify archive-index provenance separately from a maintainer-signed .dsc."""
    errors = []
    evidence = bundle.get("index_authentication", {})
    paths = {key: root / evidence.get(f"{key}_path", "") for key in ("inrelease", "index", "keyring")}
    for key, path in paths.items():
        expected = evidence.get(f"{key}_sha256", "")
        if not path.is_file() or not re.fullmatch(r"[0-9a-f]{64}", expected) or sha(path) != expected:
            errors.append(f"{package}@{version} signed-index {key} evidence is missing or corrupt")
    if errors:
        return errors
    checked = subprocess.run(["gpgv", "--keyring", str(paths["keyring"]), str(paths["inrelease"])], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if checked.returncode:
        return [f"{package}@{version} signed-index InRelease signature verification failed"]
    trust_root = evidence.get("trust_root", "")
    trusted = INDEX_TRUST_ROOTS.get(trust_root)
    if not trusted or evidence.get("keyring_sha256") != trusted[0] or not any(fp in checked.stderr.upper() for fp in trusted[1]):
        return [f"{package}@{version} signed-index trust root or signer fingerprint is not pinned"]
    release = paths["inrelease"].read_text(errors="replace")
    if not release.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        return [f"{package}@{version} signed-index InRelease is not clear-signed"]
    clear = release.split("\n\n", 1)[1].split("\n-----BEGIN PGP SIGNATURE-----", 1)[0]
    index_digest = evidence.get("index_sha256", "")
    index_size = paths["index"].stat().st_size
    if evidence.get("index_size") != index_size:
        return [f"{package}@{version} signed source index size mismatch"]
    index_relative = evidence.get("index_release_path", "")
    authenticated = any(len(parts := line.split()) == 3 and parts[0] == index_digest and parts[1] == str(index_size) and parts[2] == index_relative for line in clear.splitlines())
    if not authenticated:
        return [f"{package}@{version} signed InRelease does not authenticate the exact source index"]
    try:
        if sha(paths["index"]) != index_digest:
            return [f"{package}@{version} signed source index digest mismatch"]
        matches = [row for row in parse_deb822_index(paths["index"]) if row.get("Package") == package and row.get("Version") == version]
        if len(matches) != 1:
            return [f"{package}@{version} exact source package/version is absent or duplicated in signed index"]
        row = matches[0]
        dsc = root / bundle.get("signed_dsc_path", "")
        if not dsc.is_file() or sha(dsc) != bundle.get("signed_dsc_sha256"):
            return [f"{package}@{version} index-authenticated .dsc is missing or corrupt"]
        expected = parse_sha256_members(row.get("Checksums-Sha256") or "")
        supplied = {}
        for item in bundle.get("files", []):
            filename = item.get("filename", Path(item.get("path", "")).name)
            file_path = root / item.get("path", "")
            if filename in supplied or not file_path.is_file():
                return [f"{package}@{version} signed-index source member is missing or duplicated"]
            supplied[filename] = (item.get("sha256"), file_path.stat().st_size)
        dsc_name = bundle.get("signed_dsc_filename", dsc.name)
        index_supplied = dict(supplied)
        index_supplied[dsc_name] = (sha(dsc), dsc.stat().st_size)
        if expected != index_supplied:
            return [f"{package}@{version} signed index does not bind the complete exact source archive set"]
        fields = parse_dsc_control(dsc)
        dsc_files = parse_sha256_members(fields.get("Checksums-Sha256") or "")
        if fields.get("Source", "").split()[0] != package or fields.get("Version") != version or dsc_files != supplied:
            return [f"{package}@{version} index-authenticated source set differs from exact .dsc identity/checksums"]
        if evidence.get("trust_route") != "signed-repository-index":
            return [f"{package}@{version} signed-index trust route is not explicitly identified"]
    except (OSError, ValueError, IndexError, TypeError):
        return [f"{package}@{version} signed-index source metadata is invalid"]
    return errors


def purl(package: dict) -> str | None:
    for ref in package.get("externalRefs", []):
        if ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return package.get("purl")


def spdx_dnf(expression: str) -> list[tuple[str, ...]]:
    """Parse SPDX AND/OR precedence into alternatives of conjunctive terms."""
    tokens = re.findall(r"\(|\)|\bAND\b|\bOR\b|\bWITH\b|[A-Za-z0-9.+-]+", expression)
    if "".join(tokens).lower() != re.sub(r"\s+", "", expression).lower():
        raise ValueError("unsupported SPDX expression syntax")
    position = 0
    def atom():
        nonlocal position
        if position >= len(tokens): raise ValueError("incomplete SPDX expression")
        if tokens[position] == "(":
            position += 1; value = or_expr()
            if position >= len(tokens) or tokens[position] != ")": raise ValueError("unbalanced SPDX expression")
            position += 1
        else:
            value = [(tokens[position],)]; position += 1
        if position < len(tokens) and tokens[position] == "WITH":
            position += 1
            if position >= len(tokens): raise ValueError("incomplete SPDX WITH expression")
            exception = tokens[position]; position += 1
            value = [tuple(list(term) + ["WITH", exception]) for term in value]
        return value
    def and_expr():
        nonlocal position
        value = atom()
        while position < len(tokens) and tokens[position] == "AND":
            position += 1; right = atom()
            value = [tuple(a + b) for a in value for b in right]
        return value
    def or_expr():
        nonlocal position
        value = and_expr()
        while position < len(tokens) and tokens[position] == "OR":
            position += 1; value += and_expr()
        return value
    result = or_expr()
    if position != len(tokens): raise ValueError("unexpected SPDX expression token")
    return sorted(set(tuple(sorted(term)) for term in result))


def validate_source_disposition(candidate: dict, disposition: dict, root: Path) -> list[str]:
    """Validate a completed disposition against exact declaration and copyright identities."""
    pkg, version = candidate.get("source_package"), candidate.get("source_version")
    prefix = f"Debian source disposition {pkg}@{version}"
    errors = []
    if disposition.get("status") != "resolved" or disposition.get("source_package") != pkg or disposition.get("source_version") != version:
        return [f"{prefix} is pending or stale"]
    declarations = candidate.get("license_declarations", [])
    resolutions = disposition.get("declaration_resolutions")
    if not isinstance(resolutions, list) or len(resolutions) != len(declarations):
        return [f"{prefix} does not resolve every exact SPDX declaration"]
    unresolved = []
    for declaration in declarations:
        matches = [x for x in resolutions if x.get("spdx_expression") == declaration.get("spdx_expression") and x.get("copyright_sha256") == declaration.get("copyright_sha256")]
        if len(matches) != 1:
            unresolved.append(declaration.get("spdx_expression", "<unknown>")); continue
        item = matches[0]
        if item.get("status") != "resolved":
            unresolved.append(declaration.get("spdx_expression", "<unknown>")); continue
        decision = disposition.get("decision")
        if decision == "excluded":
            try:
                allowed = spdx_dnf(declaration.get("spdx_expression", ""))
                selected = tuple(sorted(item.get("satisfied_license_term", [])))
                if selected not in allowed or not item.get("covered_file_pattern_evidence") or not re.fullmatch(r"[0-9a-f]{64}", item.get("reviewed_source_file_sha256", "")):
                    unresolved.append(declaration.get("spdx_expression", "<unknown>"))
            except ValueError:
                unresolved.append(declaration.get("spdx_expression", "<unknown>"))
        elif decision not in {"source-bundle", "written-offer"}:
            unresolved.append(declaration.get("spdx_expression", "<unknown>"))
    if unresolved:
        errors.append(f"{prefix} has unresolved OR/AND declaration resolution: {', '.join(sorted(set(unresolved)))}")
    expected_stanzas = []
    for copyright_file in candidate.get("copyright_files", []):
        path = root / copyright_file.get("inventory_file", "")
        if not path.is_file() or sha(path) != copyright_file.get("sha256"):
            errors.append(f"{prefix} copyright file is missing or corrupt for stanza review")
            continue
        for paragraph in re.split(r"\n\s*\n", path.read_text(errors="replace").strip()):
            fields = Parser().parsestr(paragraph)
            patterns = (fields.get("Files") or "").split()
            if not patterns:
                continue
            normalized = "\n".join(line.rstrip() for line in paragraph.strip().splitlines()) + "\n"
            expected_stanzas.append((copyright_file.get("path"), copyright_file.get("sha256"), hashlib.sha256(normalized.encode()).hexdigest(), tuple(patterns)))
    declared_stanzas = {(x.get("copyright_path"), x.get("copyright_sha256"), x.get("stanza_sha256"), tuple(x.get("files_patterns", []))) for x in candidate.get("file_stanzas", [])}
    if not expected_stanzas or len(declared_stanzas) != len(candidate.get("file_stanzas", [])) or set(expected_stanzas) != declared_stanzas:
        errors.append(f"{prefix} does not enumerate every exact copyright Files stanza")
    stanza_resolutions = disposition.get("file_stanza_resolutions")
    if not isinstance(stanza_resolutions, list) or len(stanza_resolutions) != len(expected_stanzas):
        errors.append(f"{prefix} has no complete exact file-stanza disposition")
    else:
        for copyright_path, copyright_sha, stanza_sha, patterns in expected_stanzas:
            matches = [x for x in stanza_resolutions if x.get("copyright_path") == copyright_path and x.get("copyright_sha256") == copyright_sha and x.get("stanza_sha256") == stanza_sha and tuple(x.get("files_patterns", [])) == patterns]
            bound_source = disposition.get("source_bundle", {})
            exact_source_binding = disposition.get("decision") != "source-bundle" or (matches and matches[0].get("source_package") == pkg and matches[0].get("source_version") == version and matches[0].get("source_bundle_sha256") == bound_source.get("sha256"))
            if len(matches) != 1 or matches[0].get("status") != "resolved" or matches[0].get("action") != disposition.get("decision") or not exact_source_binding:
                errors.append(f"{prefix} file stanza {stanza_sha} is unresolved or mismatched")
                break
    if disposition.get("decision") == "source-bundle":
        bundle = disposition.get("source_bundle", {})
        path = root / bundle.get("path", "")
        dsc = root / bundle.get("signed_dsc_path", "")
        if bundle.get("source_package") != pkg or bundle.get("source_version") != version or not path.is_file() or sha(path) != bundle.get("sha256") or not dsc.is_file() or sha(dsc) != bundle.get("signed_dsc_sha256"):
            errors.append(f"{prefix} source archive or signed .dsc evidence is missing, stale or mismatched")
        else:
            try:
                fields = parse_dsc_control(dsc)
                if not fields.get("Source") or fields.get("Source").split()[0] != pkg or fields.get("Version") != version:
                    errors.append(f"{prefix} .dsc Source/Version identity does not match")
                expected_files = {}
                for line in (fields.get("Checksums-Sha256") or "").splitlines():
                    parts = line.split()
                    if len(parts) == 3: expected_files[parts[2]] = parts[0]
                supplied = {}
                for row in bundle.get("files", []):
                    item_path = root / row.get("path", "")
                    if not item_path.is_file() or sha(item_path) != row.get("sha256"):
                        errors.append(f"{prefix} source archive file is missing or corrupt")
                    supplied[row.get("filename", item_path.name)] = row.get("sha256")
                if not expected_files or expected_files != supplied:
                    errors.append(f"{prefix} source files do not exactly satisfy the .dsc SHA-256 list")
                if bundle.get("index_authentication"):
                    errors.extend(verify_signed_index_bundle(bundle, root, pkg, version))
                else:
                    signature = bundle.get("signature_verification", {})
                    keyring = root / signature.get("keyring_path", "")
                    if signature.get("result") != "valid" or not keyring.is_file() or sha(keyring) != signature.get("keyring_sha256") or signature.get("keyring_sha256") != DEBIAN_DEVELOPER_KEYRING_SHA256:
                        errors.append(f"{prefix} trusted developer keyring evidence is missing or corrupt")
                    else:
                        check = subprocess.run(["gpgv", "--keyring", str(keyring), str(dsc)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        if check.returncode:
                            errors.append(f"{prefix} signed .dsc signature verification failed")
            except (OSError, IndexError, ValueError, TypeError):
                errors.append(f"{prefix} .dsc metadata is invalid")
    elif disposition.get("decision") == "written-offer":
        offer = disposition.get("written_offer", {})
        path = root / offer.get("path", "")
        if not path.is_file() or sha(path) != offer.get("sha256") or not offer.get("scope") or not offer.get("validity"):
            errors.append(f"{prefix} written-offer text is missing or incomplete")
        if offer.get("valid_until"):
            try:
                if date.fromisoformat(offer["valid_until"]) < date.today():
                    errors.append(f"{prefix} written offer is expired")
            except ValueError:
                errors.append(f"{prefix} written offer expiry date is invalid")
    return errors


def validate_supplemental_python_license(root: Path, disposition: dict, errors: list[str]) -> None:
    """Authenticate a supplemental text against its pinned source archive."""
    try:
        pins = json.loads((Path(__file__).resolve().parents[2] / "third-party/notices/PYTHON-SUPPLEMENTAL-LICENSES.json").read_text())
        pin = next(x for x in pins if x["package"] == disposition.get("package") and x["version"] == disposition.get("version"))
        sources = disposition.get("source_material", [])
        if len(sources) != 1 or sources[0].get("path") != pin["source_url"]:
            raise ValueError("supplemental licence source identity mismatch")
        source = root / sources[0]["inventory_file"]
        if source.stat().st_size != pin["source_size"] or sha(source) != pin["source_sha256"]:
            raise ValueError("supplemental licence source digest mismatch")
        texts = disposition.get("license_texts", [])
        if len(texts) != 1:
            raise ValueError("supplemental licence requires the exact text")
        text = root / texts[0]["inventory_file"]
        if sha(text) != pin["license_sha256"] or disposition.get("license_expression") != pin["license_expression"]:
            raise ValueError("supplemental licence text or grant mismatch")
        with tarfile.open(source) as archive:
            stream = archive.extractfile(pin["source_member"])
            if stream is None or stream.read(1_000_001) != text.read_bytes():
                raise ValueError("supplemental licence is not the exact source member")
    except (OSError, ValueError, TypeError, KeyError, StopIteration, tarfile.TarError) as exc:
        errors.append(f"supplemental Python licence binding is invalid: {exc}")


def validate_pip_launcher_binding(root: Path, disposition: dict, errors: list[str]) -> None:
    """Recheck retained wheel members against target bytes without network access."""
    try:
        pinned = json.loads((Path(__file__).resolve().parents[2] / "third-party/notices/VENDORED-LAUNCHERS.json").read_text())["pip_launchers"]
        sources = disposition.get("source_material", [])
        wheels = [x for x in sources if x.get("path") == pinned["wheel_url"]]
        if len(wheels) != 1:
            raise ValueError("exact retained pip wheel is missing or duplicated")
        wheel = root / wheels[0]["inventory_file"]
        if wheel.stat().st_size != pinned["wheel_size"] or sha(wheel) != pinned["wheel_sha256"]:
            raise ValueError("retained pip wheel differs from pinned source")
        files = json.loads((root / "notices/image-license-files.json").read_text())
        launchers = json.loads((root / "notices/launcher-artifacts.json").read_text())
        content = disposition.get("content_sha256", [])
        expected_paths = {pinned["launcher_root"] + name for name in pinned["launcher_files"]}
        for rows, label in ((launchers, "launcher"), (content, "disposition"), (files, "image")):
            actual = ["/" + x.get("path", "").lstrip("/") for x in rows
                      if "/pip/_vendor/distlib/" in "/" + x.get("path", "") and x.get("path", "").endswith(".exe")]
            if Counter(actual) != Counter(expected_paths):
                raise ValueError(f"pip {label} target set differs from pinned wheel")
        by_path = {"/" + x["path"].lstrip("/"): x for x in files}
        with zipfile.ZipFile(wheel) as archive:
            for name, expected in pinned["launcher_files"].items():
                path = pinned["launcher_root"] + name
                source = archive.read(expected["archive_path"])
                source_hash = hashlib.sha256(source).hexdigest()
                image = by_path[path]
                launcher = next(x for x in launchers if x.get("path") == path)
                entry = next(x for x in content if x.get("path") == path)
                target = root / launcher["inventory_file"]
                if (len(source) != expected["size"] or source_hash != expected["sha256"]
                    or image.get("sha256") != source_hash or image.get("size") != len(source)
                    or launcher.get("sha256") != source_hash or target.read_bytes() != source
                    or entry.get("sha256") != source_hash or entry.get("size") != len(source)
                    or entry.get("source_archive_path") != expected["archive_path"]
                    or entry.get("source_sha256") != source_hash or entry.get("source_size") != len(source)):
                    raise ValueError(f"pip target differs from retained source wheel: {path}")
    except (OSError, ValueError, TypeError, KeyError, StopIteration, zipfile.BadZipFile) as exc:
        errors.append(f"pip launcher source binding is invalid: {exc}")


def validate_sbom_pair(root: Path, image_id: str, errors: list[str]) -> None:
    """Check supported Syft native/SPDX output identities and immutable binding."""
    try:
        native = json.loads((root / "sbom.syft.json").read_text())
        spdx = json.loads((root / "sbom.spdx.json").read_text())
        if not isinstance(native.get("artifacts"), list) or not native.get("artifacts"):
            errors.append("Syft SBOM artifacts list is empty or invalid"); return
        source = native.get("source", {})
        if source.get("type") != "image" or source.get("metadata", {}).get("userInput") != image_id:
            errors.append("Syft SBOM image binding does not match the immutable image ID")
        if source.get("metadata", {}).get("manifestDigest", "").startswith("sha256:") is False:
            errors.append("Syft SBOM manifest digest is missing")
        if native.get("distro", {}).get("id") != "debian":
            errors.append("Syft SBOM distribution identity is missing or unsupported")
        launcher_rows = json.loads((root / "notices/launcher-artifacts.json").read_text()) if (root / "notices/launcher-artifacts.json").is_file() else []
        launcher_paths = {x.get("path") for x in launcher_rows}
        native_rows = []
        for x in native["artifacts"]:
            locations = {loc.get("path") for loc in x.get("locations", [])}
            if x.get("type") == "binary" and locations and locations <= launcher_paths:
                continue
            native_rows.append(x)
        native_ids = [(x.get("name"), x.get("version"), x.get("purl")) for x in native_rows]
        if any(not n or not v or v == "UNKNOWN" for n, v, _ in native_ids):
            errors.append("Syft SBOM contains package identity with missing name/version outside classified launchers")
        spdx_rows = spdx.get("packages")
        if not isinstance(spdx_rows, list) or not spdx_rows:
            errors.append("SPDX SBOM package list is empty or invalid"); return
        spdx_ids = [(x.get("name"), x.get("versionInfo"), purl(x)) for x in spdx_rows]
        launcher_identities = {(x.get("catalog_name"), x.get("catalog_version")) for x in launcher_rows}
        native_pkg = sorted((n, v, u) for n, v, u in native_ids if n != "sha256")
        spdx_pkg = sorted((n, v, u) for n, v, u in spdx_ids if n != "sha256" and (n, v) not in launcher_identities)
        if native_pkg != spdx_pkg:
            errors.append("Syft and SPDX package identity/version/location sets differ")
        oci = [u for n, _, u in spdx_ids if n == "sha256" and u and u.startswith("pkg:oci/sha256@sha256%3A")]
        if len(oci) != 1 or source.get("metadata", {}).get("manifestDigest", "").removeprefix("sha256:") not in oci[0]:
            errors.append("SPDX image package binding does not match the Syft manifest digest")
        declared = {(x.get("name"), x.get("versionInfo")): x.get("licenseDeclared") for x in spdx_rows}
        evidence = json.loads((root / "notice-manifest.json").read_text()).get("package_license_evidence", [])
        covered = {(x.get("name"), x.get("version")): x for x in evidence}
        launcher_names = launcher_identities
        launcher_name_set = {name for name, _ in launcher_names}
        for (name, version), license_id in declared.items():
            if license_id == "NOASSERTION" and name != "sha256":
                row = covered.get((name, version))
                if (not row or not (row.get("license_evidence") or row.get("metadata_license_texts"))) and name not in launcher_name_set:
                    errors.append(f"SPDX NOASSERTION lacks joined license/text evidence: {name}@{version}")
        # Rejoin every native package identity (including its location set) to
        # captured text or an exact separately validated disposition.
        files = json.loads((root / "notices/image-license-files.json").read_text())
        file_by_path = {"/" + x.get("path", "").lstrip("/"): x for x in files}
        placeholder = {"", "NOASSERTION", "UNKNOWN", "NONE"}
        dispositions = json.loads((root / "notices/package-license-dispositions.json").read_text())
        disposition_names = {(x.get("package", "").lower(), str(x.get("version", ""))) for x in dispositions}
        disposition_names.update(("python", version) for name, version in list(disposition_names)
                                 if name == "cpython" and re.fullmatch(r"3\.14\.\d+", version))
        ui = json.loads((root / "notices/ui-bundled-license-assets.json").read_text())
        ui_names = {(x.get("name"), str(x.get("version"))) for x in ui.get("packages", [])}
        evidence_by_identity = {json.dumps(x.get("identity"), sort_keys=True): x for x in evidence if x.get("identity")}
        native_expected = []
        for package in native_rows:
            key = json.dumps({"type": package.get("type"), "name": package.get("name"), "version": package.get("version"), "purl": package.get("purl"), "locations": sorted({loc.get("path", "") for loc in package.get("locations", [])})}, sort_keys=True)
            native_expected.append(key)
            row = evidence_by_identity.get(key)
            if not row:
                errors.append(f"package identity has no license evidence join: {package.get('name')}@{package.get('version')}")
                continue
            native_grants = {str(x.get("spdxExpression") or x.get("value") or "").strip() for x in package.get("licenses", [])}
            native_grants = {x for x in native_grants if x.upper() not in placeholder}
            evidence_grants = {str(x.get("spdx_expression") or x.get("value") or "").strip() for x in row.get("license_evidence", [])}
            evidence_grants = {x for x in evidence_grants if x.upper() not in placeholder}
            metadata_identity = row.get("metadata_license_identity", {})
            metadata_name = str(package.get("name", "")).lower().replace("_", "-")
            package_locations = [x.get("path", "") for x in package.get("locations", [])]
            package_roots = {x.split("/site-packages/", 1)[0] + "/site-packages" for x in package_locations if "/site-packages/" in x}
            metadata_path_abs = "/" + str(metadata_identity.get("metadata_path", "")).lstrip("/")
            metadata_exact = (metadata_identity.get("name") == metadata_name and str(metadata_identity.get("version")) == str(package.get("version"))
                and metadata_identity.get("install_location") in package_roots
                and metadata_path_abs.startswith(str(metadata_identity.get("install_location", "")) + "/")
                and file_by_path.get(metadata_path_abs, {}).get("sha256") == metadata_identity.get("metadata_sha256")) if package_roots else False
            metadata_hints = [str(x).strip() for x in row.get("metadata_license_hints", []) if str(x).strip().upper() not in placeholder]
            metadata_classifiers = [str(x).strip() for x in row.get("metadata_license_classifiers", []) if str(x).strip().upper() not in placeholder]
            paired_metadata_texts = []
            if metadata_exact:
                metadata_dist_info = "/" + str(metadata_identity.get("metadata_path", "")).lstrip("/").rsplit("/", 1)[0]
                for text in row.get("metadata_license_texts", []):
                    path = "/" + str(text.get("path", "")).lstrip("/")
                    item = file_by_path.get(path)
                    if (item and re.match(r"^(licen[cs]e|copying|copyright|notice)([._-]|$)", Path(path).name, re.I)
                        and text.get("version") == str(package.get("version")) and text.get("install_location") in package_roots
                        and path.startswith(metadata_dist_info + "/") and path.startswith(str(text.get("install_location")) + "/")
                        and item.get("sha256") == text.get("sha256")):
                        paired_metadata_texts.append(path)
            license_paths = {loc.get("path") for lic in row.get("license_evidence", []) if str(lic.get("spdx_expression") or lic.get("value") or "").strip().upper() not in placeholder for loc in lic.get("locations", [])}
            # A declaration in METADATA is not a retained licence text. Python
            # texts must be joined to the exact installed distribution/version.
            distribution_dirs = {path.rsplit("/", 1)[0] for path in package_locations
                                 if ".dist-info/" in path}
            native_python_texts = {path for path in license_paths if path in file_by_path
                                   and re.match(r"^(licen[cs]e|copying|copyright|notice)([._-]|$)", Path(path).name, re.I)
                                   and any(path.startswith(directory + "/") for directory in distribution_dirs)}
            has_text = (bool(paired_metadata_texts or native_python_texts) if package.get("type") == "python"
                        else any(path in file_by_path for path in license_paths))
            if package.get("type") == "python" and metadata_exact and package.get("name") == "fontawesomefree":
                # The distribution ships the notice with its static assets,
                # outside dist-info; bind it to this installation's metadata.
                has_text = has_text or (metadata_identity["install_location"] +
                    "/fontawesomefree/static/fontawesomefree/LICENSE.txt") in file_by_path
            has_fontawesome_text = any(path.endswith("/" + str(package.get("name", "")) + "/LICENSE.txt") and "fontawesomefree/static/fontawesomefree/js-packages/" in path for path in file_by_path)
            has_ui_asset = (package.get("name"), str(package.get("version"))) in ui_names
            has_explicit_disposition = (str(package.get("name", "")).lower(), str(package.get("version", ""))) in disposition_names
            if not (has_text or has_fontawesome_text or has_ui_asset or has_explicit_disposition):
                errors.append(f"package license text has no package/version/path join: {package.get('name')}@{package.get('version')}")
            resolved_expression = bool(native_grants or evidence_grants or ((metadata_hints or metadata_classifiers) and paired_metadata_texts))
            if not resolved_expression and not has_explicit_disposition and not has_ui_asset:
                errors.append(f"package license expression is unknown: {package.get('name')}@{package.get('version')}")
        if Counter(native_expected) != Counter(evidence_by_identity.keys()):
            errors.append("per-package license evidence identity set differs from native SBOM package identities")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        errors.append(f"SBOM semantic validation failed: {exc}")


def validate_source_sbom_binding(root: Path, source_id: str, errors: list[str]) -> None:
    try:
        doc = json.loads((root / "sbom.valkey-source.syft.json").read_text())
        if not IMAGE_RE.fullmatch(source_id) or doc.get("source", {}).get("metadata", {}).get("userInput") != source_id:
            errors.append("pinned source-image SBOM binding does not match admitted source image ID")
        if not isinstance(doc.get("artifacts"), list) or not doc["artifacts"]:
            errors.append("pinned source-image SBOM package inventory is empty")
    except (OSError, ValueError, TypeError):
        errors.append("pinned source-image SBOM is invalid")


def validate_source_image_admission(root: Path, provenance: dict, errors: list[str]) -> None:
    """Bind admitted local image identity to the exact Dockerfile-pinned repository digest."""
    try:
        admission = provenance.get("source_distribution_admission", {})
        source_id = provenance.get("source_image_id", "")
        reference = admission.get("reference", "")
        registry_digest = admission.get("registry_digest", "")
        local_id = admission.get("local_image_id", "")
        if (not isinstance(reference, str) or "@" not in reference
                or not IMAGE_RE.fullmatch(registry_digest)
                or reference.rsplit("@", 1)[1] != registry_digest
                or local_id != source_id
                or admission.get("platform") != "linux/amd64"
                or not IMAGE_RE.fullmatch(local_id)):
            errors.append("pinned source-image admission identities are invalid")
            return
        dockerfile = (root / "notices/reference-sources/Dockerfile.g7").read_text()
        match = re.search(r"^ARG VALKEY_IMAGE=([^\n]+)$", dockerfile, re.MULTILINE)
        if not match or match.group(1) != reference:
            errors.append("source-image admission reference does not match retained Dockerfile")
        repository = reference.rsplit("@", 1)[0].rsplit("/", 1)
        repository = repository[0] + "/" + repository[1].split(":", 1)[0]
        if f"{repository}@{registry_digest}" not in admission.get("repo_digests", []):
            errors.append("source-image admission lacks the exact pinned repository digest")
    except (OSError, ValueError, TypeError, AttributeError):
        errors.append("source-image admission evidence is invalid")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--directory", required=True, type=Path, help="collector output directory")
    ap.add_argument("--image", help="expected immutable image ID (recommended for release binding)")
    args = ap.parse_args()
    root = args.directory.resolve()
    manifest_path = root / "notice-manifest.json"
    try:
        m = json.loads(manifest_path.read_text())
        errors = []
        if m.get("schema") != "volt-notice-inventory/v1": errors.append("unsupported manifest schema")
        if not IMAGE_RE.fullmatch(m.get("image_id", "")): errors.append("manifest image ID is not immutable")
        if args.image and args.image != m.get("image_id"): errors.append("manifest image ID does not match expected image")
        if m.get("platform") != "linux/amd64": errors.append("platform is not linux/amd64")
        validate_sbom_pair(root, m.get("image_id", ""), errors)
        files = m.get("files")
        if not isinstance(files, list): errors.append("manifest file list missing")
        else:
            seen = set()
            for row in files:
                rel = row.get("path", "")
                p = (root / rel).resolve()
                if p == root or root not in p.parents or rel in seen:
                    errors.append(f"invalid or duplicate artifact path: {rel}"); continue
                seen.add(rel)
                if not p.is_file(): errors.append(f"artifact missing: {rel}")
                elif sha(p) != row.get("sha256"): errors.append(f"artifact digest mismatch: {rel}")
        for required in ("sbom.syft.json", "sbom.spdx.json", "sbom.valkey-source.syft.json", "notices/VOLT-THIRD-PARTY-NOTICES.md", "notices/VOLT-LICENSE.txt", "notices/OPENSSL-APACHE-2.0.txt", "notices/DISTLIB-LAUNCHER-BSD-2.txt", "notices/SETUPTOOLS-84.0.0-MIT-LICENSE.txt", "notices/MUSL-1.2.6-COPYRIGHT", "notices/MUSL-LICENSE-EVIDENCE.json", "notices/embedded-notice-assets.json", "notices/image-license-files.json", "notices/python-distribution-license-evidence.json", "notices/copied-binary-provenance.json", "notices/copied-source-file-hashes.json", "notices/docker-cleanup-records.json", "notices/ui-production-lock-licenses.json", "notices/ui-bundled-license-assets.json", "notices/debian-source-packages.json", "notices/debian-source-candidates.json", "notices/launcher-artifacts.json", "notices/package-license-dispositions.json"):
            if not (root / required).is_file(): errors.append(f"required artifact missing: {required}")
        try:
            image_files = json.loads((root / "notices/image-license-files.json").read_text())
            launcher_files = json.loads((root / "notices/launcher-artifacts.json").read_text())
            captured_pip = any("/pip/_vendor/distlib/" in "/" + x.get("path", "") and x.get("path", "").endswith(".exe") for x in image_files + launcher_files)
            if captured_pip and not (root / "notices/PIP-26.2.1-DISTLIB-LICENSE.txt").is_file():
                errors.append("required artifact missing: notices/PIP-26.2.1-DISTLIB-LICENSE.txt")
        except (OSError, ValueError, TypeError):
            pass
        try:
            provenance = json.loads((root / "notices/copied-binary-provenance.json").read_text())
            expected_assets = {"/opt/valkey/bin/valkey-server", "/opt/valkey/bin/valkey-cli", "/opt/valkey/lib/ld-musl-x86_64.so.1", "/opt/valkey/lib/libc.musl-x86_64.so.1", "/opt/valkey/lib/libssl.so.3", "/opt/valkey/lib/libcrypto.so.3"}
            copied = {x.get("path"): x for x in provenance.get("copied_assets", []) if isinstance(x, dict)}
            if set(copied) != expected_assets or provenance.get("missing_assets"): errors.append("copied-binary provenance coverage is incomplete")
            for path, row in copied.items():
                if not re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", "")) or not isinstance(row.get("size"), int) or row["size"] <= 0:
                    errors.append(f"copied-binary digest/size evidence is invalid: {path}")
            source_id = provenance.get("source_image_id", "")
            if not IMAGE_RE.fullmatch(source_id) or provenance.get("source_image_platform") != "linux/amd64": errors.append("copied-binary source image is not bound to a linux/amd64 immutable ID")
            validate_source_image_admission(root, provenance, errors)
            if not isinstance(provenance.get("source_image_package_evidence"), dict): errors.append("copied-binary source package evidence is missing")
            validate_source_sbom_binding(root, source_id, errors)
            source_files = provenance.get("source_files", {})
            target_files = {"/" + x.get("path", ""): x for x in json.loads((root / "notices/image-license-files.json").read_text()) if x.get("kind") == "copied-runtime-binary"}
            if set(source_files) != expected_assets:
                errors.append("copied-binary source file hash coverage is incomplete")
            for target_path in expected_assets:
                source_row, target_row = source_files.get(target_path, {}), target_files.get(target_path, {})
                if not source_row.get("resolved_source_path") or source_row.get("sha256") != target_row.get("sha256") or source_row.get("size") != target_row.get("size"):
                    errors.append(f"copied binary differs from pinned source-image bytes: {target_path}")
        except (OSError, ValueError, TypeError):
            errors.append("copied-binary provenance is invalid")
        try:
            ui = json.loads((root / "notices/ui-production-lock-licenses.json").read_text())
            for package in ui:
                if not package.get("declared_license") or not package.get("license_files"):
                    errors.append(f"runtime UI package has incomplete license coverage: {package.get('name', '<unknown>')}")
        except (OSError, ValueError, TypeError):
            errors.append("runtime UI package license inventory is invalid")
        try:
            groups = json.loads((root / "notices/debian-source-packages.json").read_text())
            keys = [(x.get("source_package"), x.get("source_version")) for x in groups]
            if len(keys) != len(set(keys)): errors.append("Debian source package grouping contains duplicates")
            for group in groups:
                if not group.get("source_package") or not group.get("source_version") or not group.get("source_action"):
                    errors.append("Debian source package action/evidence is incomplete")
                for ref in group.get("copyright_files", []):
                    target = root / ref.get("inventory_file", "")
                    if not target.is_file() or sha(target) != ref.get("sha256"):
                        errors.append(f"Debian copyright evidence missing or corrupt: {ref.get('path')}")
                for declaration in group.get("license_declarations", []):
                    expr = declaration.get("spdx_expression", "")
                    if expr and (" OR " in expr or " AND " in expr):
                        # Keep expression semantics intact; flattening them into
                        # per-token obligations is explicitly not accepted.
                        if declaration.get("value") == expr and "(" in expr and (" OR " in expr or " AND " in expr):
                            continue
        except (OSError, ValueError, TypeError):
            errors.append("Debian source package evidence is invalid")
        try:
            candidates = json.loads((root / "notices/debian-source-candidates.json").read_text())
            groups = json.loads((root / "notices/debian-source-packages.json").read_text())
            group_keys = {(x.get("source_package"), x.get("source_version")) for x in groups}
            for candidate in candidates:
                if (candidate.get("source_package"), candidate.get("source_version")) not in group_keys or not candidate.get("license_declarations") or not candidate.get("copyright_files"):
                    errors.append("Debian source candidate is missing exact package, license, copyright or action evidence")
                disposition = candidate.get("disposition", {})
                errors.extend(validate_source_disposition(candidate, disposition, root))
            if len(candidates) != m.get("debian_source_candidate_count"):
                errors.append("Debian source candidate count does not match the detailed candidate list")
        except (OSError, ValueError, TypeError):
            errors.append("Debian source candidates are invalid")
        try:
            embedded = json.loads((root / "notices/embedded-notice-assets.json").read_text())
            if not isinstance(embedded, list) or len(embedded) != m.get("embedded_notice_asset_count"):
                errors.append("embedded notice asset inventory count is invalid")
            elif any(x.get("status") != "verified" or not re.fullmatch(r"[0-9a-f]{64}", x.get("image_sha256", "")) or x.get("image_sha256") != x.get("expected_sha256") for x in embedded):
                errors.append("one or more curated notice assets are absent or differ from the checked-in bytes in the image")
        except (OSError, ValueError, TypeError):
            errors.append("embedded notice asset evidence is invalid")
        try:
            dispositions = json.loads((root / "notices/package-license-dispositions.json").read_text())
            copied_provenance = json.loads((root / "notices/copied-binary-provenance.json").read_text())
            copied_hashes = {x.get("path"): x.get("sha256") for x in copied_provenance.get("copied_assets", [])}
            captured_pip = any("/pip/_vendor/distlib/" in "/" + x.get("path", "") and x.get("path", "").endswith(".exe")
                               for x in json.loads((root / "notices/image-license-files.json").read_text()) + json.loads((root / "notices/launcher-artifacts.json").read_text()))
            pip_dispositions = [x for x in dispositions if x.get("package") == "pip vendored distlib Windows launchers"]
            if captured_pip:
                if len(pip_dispositions) != 1 or pip_dispositions[0].get("version") != "distlib 0.4.2 via pip 26.2.1":
                    errors.append("captured pip launchers require exactly one matching versioned source disposition")
                else:
                    validate_pip_launcher_binding(root, pip_dispositions[0], errors)
            for item in dispositions:
                if item.get("package") in {"packageurl-python", "titlecase"}:
                    validate_supplemental_python_license(root, item, errors)
                if not all(item.get(k) for k in ("package", "version", "license_expression", "copyright", "license_texts", "obligation_resolution", "provenance")):
                    errors.append(f"license disposition is incomplete: {item.get('package', '<unknown>')}")
                for source in item.get("source_material", []):
                    if source.get("inventory_file"):
                        target = root / source["inventory_file"]
                        if not target.is_file() or sha(target) != source.get("sha256"):
                            errors.append(f"disposition source material missing or corrupt: {source.get('path')}")
                    elif not source.get("path", "").startswith("https://") or not re.fullmatch(r"[0-9a-f]{64}", source.get("sha256", "")):
                        errors.append(f"external disposition source lacks URL and SHA-256: {source.get('path')}")
                for text in item.get("license_texts", []):
                    target = root / text.get("inventory_file", "")
                    if not target.is_file() or sha(target) != text.get("sha256"):
                        errors.append(f"disposition license text missing or corrupt: {text.get('path')}")
                content = item.get("content_sha256", [])
                if isinstance(content, list):
                    for entry in content:
                        if isinstance(entry, dict) and entry.get("path", "").startswith("/opt/valkey/") and copied_hashes.get(entry["path"]) != entry.get("sha256"):
                            errors.append(f"copied runtime disposition digest mismatch: {entry.get('path')}")
        except (OSError, ValueError, TypeError):
            errors.append("package license dispositions are invalid")
        try:
            bundled = json.loads((root / "notices/ui-bundled-license-assets.json").read_text())
            if bundled.get("unresolved"): errors.append(f"{len(bundled['unresolved'])} bundled UI license asset findings")
            if bundled.get("package_count") != m.get("runtime_ui_packages"): errors.append("bundled UI license asset package count does not cover runtime lock closure")
        except (OSError, ValueError, TypeError):
            errors.append("bundled UI license assets manifest is invalid")
        try:
            launchers = json.loads((root / "notices/launcher-artifacts.json").read_text())
            image_files = json.loads((root / "notices/image-license-files.json").read_text())
            image_hashes = {"/" + x.get("path", ""): x.get("sha256") for x in image_files}
            if not isinstance(launchers, list): errors.append("launcher evidence is not a list")
            for item in launchers:
                target = root / item.get("inventory_file", "")
                if not item.get("path", "").endswith(".exe") or "Windows launcher" not in item.get("classification", "") or not target.is_file() or sha(target) != item.get("sha256"):
                    errors.append(f"launcher artifact evidence missing or corrupt: {item.get('path')}")
                if "/pip/_vendor/distlib/" in item.get("path", ""):
                    license_file = root / "notices/DISTLIB-LAUNCHER-BSD-2.txt"
                    if item.get("license_expression") != "BSD-2-Clause" or not license_file.is_file() or sha(license_file) != item.get("license_file_sha256"):
                        errors.append(f"distlib launcher license evidence missing or corrupt: {item.get('path')}")
                if "/site-packages/setuptools/" in item.get("path", ""):
                    license_file = root / "notices/SETUPTOOLS-84.0.0-MIT-LICENSE.txt"
                    if item.get("license_expression") != "MIT" or not license_file.is_file() or sha(license_file) != item.get("license_file_sha256"):
                        errors.append(f"setuptools launcher license evidence missing or corrupt: {item.get('path')}")
                    if image_hashes.get(item.get("path")) != item.get("sha256"):
                        errors.append(f"setuptools launcher digest is not linked to captured image file: {item.get('path')}")
            if sum("/site-packages/setuptools/" in x.get("path", "") for x in launchers) not in (0, 8):
                errors.append("setuptools launcher evidence does not cover the complete expected set")
        except (OSError, ValueError, TypeError):
            errors.append("launcher artifact evidence is invalid")
        try:
            cleanup = json.loads((root / "notices/docker-cleanup-records.json").read_text())
            if not cleanup or any(not row.get("container_id") or row.get("command") != ["docker", "rm", "--volumes", row.get("container_id")] or row.get("exit_code") != 0 for row in cleanup):
                errors.append("Docker export cleanup records are incomplete or failed")
        except (OSError, ValueError, TypeError):
            errors.append("Docker export cleanup records are invalid")
        unresolved = m.get("unresolved")
        if not isinstance(unresolved, list): errors.append("unresolved findings list missing")
        elif unresolved: errors.append(f"{len(unresolved)} unresolved license findings")
        if m.get("packages_with_license_metadata", -1) + (len(unresolved) if isinstance(unresolved, list) else 0) < m.get("package_count", 0):
            errors.append("package license metadata coverage count is incomplete")
        if errors:
            for err in errors: print(f"FAIL: {err}", file=sys.stderr)
            return 1
        print(f"PASS: {m['package_count']} image packages, image {m['image_id']}, {len(files)} hashed artifacts")
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"FAIL: invalid notice inventory: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
