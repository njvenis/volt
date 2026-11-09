#!/usr/bin/env python3
"""Create image-bound SBOMs and a fail-closed third-party notice bundle."""
from __future__ import annotations

import argparse
import hashlib
import json
from email.parser import Parser
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import base64
import zipfile
import posixpath
import os

ROOT = Path(__file__).resolve().parents[2]
IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
VALKEY_SOURCE_RE = re.compile(r"^ARG VALKEY_IMAGE=[^@\n]+@(sha256:[0-9a-f]{64})$", re.MULTILINE)
EXPECTED_COPIED_ASSETS = ["/opt/valkey/bin/valkey-server", "/opt/valkey/bin/valkey-cli", "/opt/valkey/lib/ld-musl-x86_64.so.1", "/opt/valkey/lib/libc.musl-x86_64.so.1", "/opt/valkey/lib/libssl.so.3", "/opt/valkey/lib/libcrypto.so.3"]
DEBIAN_DEVELOPER_KEYRING_SHA256 = "81e08f47b0dd8a563a2742ad90878ccefe53aa0728b095acbea3efda84381ea9"


def run(args: list[str], *, stdout=None) -> str:
    p = subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE if stdout is None else stdout, stderr=subprocess.PIPE)
    return p.stdout if stdout is None else ""


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def packages_from_sbom(path: Path) -> list[dict]:
    doc = json.loads(path.read_text())
    if "artifacts" in doc:  # Syft native JSON
        return doc["artifacts"]
    if "packages" in doc:  # SPDX JSON
        return doc["packages"]
    raise ValueError(f"unsupported Syft document shape: {path}")


def license_records(package: dict) -> list[dict]:
    vals = package.get("licenses") or package.get("licenseConcluded") or []
    if isinstance(vals, str):
        vals = [vals]
    result = []
    for item in vals:
        if isinstance(item, str):
            result.append({"value": item.strip(), "spdx_expression": item.strip(), "type": "unknown", "locations": []})
        elif isinstance(item, dict):
            result.append({"value": str(item.get("value") or "").strip(), "spdx_expression": str(item.get("spdxExpression") or "").strip(), "type": item.get("type", "unknown"), "locations": item.get("locations", [])})
    # Syft may emit duplicate license rows for the same package/location. Keep
    # each exact expression and its source attribution, without flattening OR/AND.
    unique = {json.dumps(r, sort_keys=True): r for r in result if r["value"] or r["spdx_expression"]}
    return [unique[k] for k in sorted(unique)]


def debian_source_groups(packages: list[dict], image_files: list[dict], out: Path) -> list[dict]:
    """Group Debian cataloger rows by source package; do not count license tokens as obligations."""
    by_path = {"/" + x["path"].lstrip("/"): x for x in image_files}
    groups: dict[tuple[str, str], dict] = {}
    for package in packages:
        meta = package.get("metadata") or {}
        if package.get("type") != "deb" or not meta:
            continue
        name = str(meta.get("source") or package.get("name") or "unknown")
        version = str(meta.get("sourceVersion") or package.get("version") or "unknown")
        key = (name, version)
        row = groups.setdefault(key, {"source_package": name, "source_version": version, "binary_packages": [], "copyright_files": [], "license_declarations": []})
        row["binary_packages"].append({"name": package.get("name"), "version": package.get("version")})
        for lic in license_records(package):
            for location in lic.get("locations", []):
                path = location.get("path")
                captured = by_path.get(path)
                if captured:
                    row["license_declarations"].append({"value": lic["value"], "spdx_expression": lic["spdx_expression"], "type": lic["type"], "copyright_path": path, "copyright_sha256": captured["sha256"]})
                    row["copyright_files"].append({"path": path, "sha256": captured["sha256"], "inventory_file": "notices/" + captured["file"]})
    for row in groups.values():
        row["binary_packages"] = sorted({json.dumps(x, sort_keys=True) for x in row["binary_packages"]})
        row["binary_packages"] = [json.loads(x) for x in row["binary_packages"]]
        row["copyright_files"] = [json.loads(x) for x in sorted({json.dumps(x, sort_keys=True) for x in row["copyright_files"]})]
        row["license_declarations"] = [json.loads(x) for x in sorted({json.dumps(x, sort_keys=True) for x in row["license_declarations"]})]
        row["source_action"] = "For any redistributed binary whose package-specific copyright file identifies a copyleft-covered component, include the exact matching Debian source package archive (source name/version above) with its signed .dsc and checksum-verified source files, or record the applicable written offer before distribution. This inventory does not assert which file stanza applies to each binary."
    return sorted(groups.values(), key=lambda x: (x["source_package"], x["source_version"]))


def copyright_stanzas(path: Path) -> list[dict]:
    """Return exact DEP-5 Files stanzas as hash-bound paragraphs."""
    rows = []
    for paragraph in re.split(r"\n\s*\n", path.read_text(errors="replace").strip()):
        parsed = Parser().parsestr(paragraph)
        patterns = (parsed.get("Files") or "").split()
        if not patterns:
            continue
        license_field = parsed.get("License") or ""
        normalized = "\n".join(line.rstrip() for line in paragraph.strip().splitlines()) + "\n"
        rows.append({"stanza_sha256": hashlib.sha256(normalized.encode()).hexdigest(), "files_patterns": patterns, "license": license_field.splitlines()[0].strip()})
    return rows


def debian_source_offer_candidates(groups: list[dict], dispositions: dict[tuple[str, str], dict] | None = None, root: Path | None = None) -> list[dict]:
    """Attribute possible copyleft source duties to source-package/version groups."""
    copyleft = re.compile(r"(?i)(?:^|[^a-z0-9])(?:AGPL|GPL|LGPL|MPL|EPL|EUPL|OSL|CDDL|SSPL|Sleepycat|MS-PL)(?:[^a-z0-9]|$)")
    candidates = []
    for group in groups:
        declarations = group.get("license_declarations", [])
        relevant_rows = [row for row in declarations if copyleft.search(row.get("spdx_expression", "") or row.get("value", ""))]
        # One package copyright/expression pair is a disposition unit even if
        # Syft emits the same record through multiple binary artifacts or raw
        # license aliases. Preserve those aliases as evidence without making
        # them duplicate obligations.
        relevant_by_identity = {}
        for row in relevant_rows:
            identity = (row.get("spdx_expression"), row.get("copyright_sha256"))
            item = relevant_by_identity.setdefault(identity, {**row, "observed_values": [], "observed_types": []})
            if row.get("value"):
                item["observed_values"].append(row["value"])
            if row.get("type"):
                item["observed_types"].append(row["type"])
        relevant = [{**row, "observed_values": sorted(set(row["observed_values"])), "observed_types": sorted(set(row["observed_types"]))} for row in relevant_by_identity.values()]
        relevant.sort(key=lambda x: (str(x.get("copyright_path")), str(x.get("spdx_expression")), str(x.get("copyright_sha256"))))
        if not relevant:
            continue
        key = (group["source_package"], group["source_version"])
        disposition = (dispositions or {}).get(key, {"source_package": key[0], "source_version": key[1], "status": "pending"})
        stanza_rows = []
        if root is not None:
            for cf in group["copyright_files"]:
                path = root / cf["inventory_file"]
                if path.is_file():
                    for stanza in copyright_stanzas(path):
                        stanza_rows.append({"copyright_path": cf["path"], "copyright_sha256": cf["sha256"], **stanza})
        candidates.append({"source_package": key[0], "source_version": key[1], "binary_packages": group["binary_packages"], "license_declarations": relevant, "copyright_files": group["copyright_files"], "file_stanzas": stanza_rows, "status": "resolved" if disposition.get("status") == "resolved" else "pending", "disposition": disposition, "action_choices": ["include exact source package/version archive with checksum-verified source files", "document an applicable written offer", "record exact source-file pattern evidence supporting exclusion"]})
    return candidates


def deduplicate_findings(rows: list[dict]) -> list[dict]:
    unique = {json.dumps(row, sort_keys=True): row for row in rows}
    return [unique[key] for key in sorted(unique)]


def copy_disposition_evidence(dispositions: dict[tuple[str, str], dict], root: Path, source_base: Path | None = None) -> None:
    """Retain disposition source inputs inside inventory, using hardlinks when possible."""
    destination_root = root / "notices/debian-source-material"
    for identity, disposition in dispositions.items():
        evidence_rows = []
        if disposition.get("decision") == "source-bundle":
            bundle = disposition.get("source_bundle", {})
            evidence_rows.extend([(bundle, "path"), (bundle, "signed_dsc_path")])
            evidence_rows.extend((row, "path") for row in bundle.get("files", []))
            index_auth = bundle.get("index_authentication", {})
            evidence_rows.extend((index_auth, field) for field in ("inrelease_path", "index_path", "keyring_path") if index_auth.get(field))
        elif disposition.get("decision") == "written-offer":
            evidence_rows.append((disposition.get("written_offer", {}), "path"))
        for record, field in evidence_rows:
            supplied_path = Path(str(record.get(field, "")))
            if not supplied_path.is_absolute():
                supplied_path = (source_base or Path.cwd()) / supplied_path
            supplied_path = supplied_path.resolve()
            if field == "path": record.setdefault("filename", supplied_path.name)
            hash_field = {"path": "sha256", "signed_dsc_path": "signed_dsc_sha256", "inrelease_path": "inrelease_sha256", "index_path": "index_sha256", "keyring_path": "keyring_sha256"}[field]
            expected = record.get(hash_field)
            if not supplied_path.is_file() or not re.fullmatch(r"[0-9a-f]{64}", str(expected or "")) or digest(supplied_path) != expected:
                raise ValueError(f"Debian disposition evidence file missing or SHA-256 mismatch: {supplied_path}")
            name = f"{re.sub(r'[^A-Za-z0-9.+_-]', '_', identity[0])}-{identity[1]}-{hashlib.sha256(str(supplied_path).encode()).hexdigest()[:12]}-{supplied_path.name}"
            target = destination_root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                if digest(target) != expected: raise ValueError("existing Debian disposition evidence path has different bytes")
            else:
                try:
                    os.link(supplied_path, target)
                except OSError:
                    if shutil.disk_usage(root).free < supplied_path.stat().st_size:
                        raise ValueError("insufficient free space to retain Debian disposition evidence")
                    shutil.copyfile(supplied_path, target)
            record[field] = target.relative_to(root).as_posix()


def pygithub_license_expression(source_text: str) -> str | None:
    """Return only the grant stated by the captured installed source header."""
    normalized = source_text.casefold()
    if "gnu lesser general public license" in normalized and "any later version" in normalized:
        return "LGPL-3.0-or-later"
    return None


def verify_bundled_ui_assets(lock: dict) -> dict:
    asset_dir = ROOT / "third-party/notices"
    manifest_path = asset_dir / "ui-production-license-assets.json"
    manifest = json.loads(manifest_path.read_text())
    packages = {x.get("name"): x for x in manifest.get("packages", [])}
    expected = {}
    for key, value in lock.get("packages", {}).items():
        if key and not value.get("dev"):
            expected[key.removeprefix("node_modules/")] = value
    errors = []
    rows = []
    for name, lock_row in sorted(expected.items()):
        row = packages.get(name)
        if not row or row.get("version") != lock_row.get("version") or row.get("integrity") != lock_row.get("integrity"):
            errors.append({"name": name, "version": lock_row.get("version"), "reason": "checked-in UI notice manifest does not match production lock identity/integrity"})
            continue
        text_path = (asset_dir / row.get("license_file", "")).resolve()
        if asset_dir.resolve() not in text_path.parents or not text_path.is_file() or digest(text_path) != row.get("license_file_sha256"):
            errors.append({"name": name, "version": row.get("version"), "reason": "bundled UI license text missing or corrupt"})
            continue
        if not row.get("declared_license") or not row.get("package_license_archive_sha256") or not row.get("package_license_archive_path"):
            errors.append({"name": name, "version": row.get("version"), "reason": "bundled UI license attribution lacks package archive text evidence"})
            continue
        rows.append(row)
    if set(packages) != set(expected):
        errors.append({"name": "<manifest>", "reason": "checked-in UI notice manifest package set differs from production lock"})
    return {"schema": manifest.get("schema"), "package_count": len(rows), "packages": rows, "unresolved": errors}


def verify_setuptools_launcher_evidence(image_files: list[dict], dest: Path) -> tuple[dict | None, dict | None]:
    """Verify launcher bytes against the checksum-pinned exact wheel and its license text."""
    asset_dir = ROOT / "third-party/notices"
    manifest = json.loads((asset_dir / "SETUPTOOLS-LAUNCHERS.json").read_text())
    license_path = asset_dir / manifest["license_file"]
    if digest(license_path) != manifest.get("license_file_sha256"):
        raise ValueError("setuptools launcher license asset digest does not match its evidence manifest")
    url = manifest.get("wheel_url")
    with urllib.request.urlopen(url, timeout=30) as response:
        wheel = response.read(5_000_001)
    if len(wheel) > 5_000_000 or hashlib.sha256(wheel).hexdigest() != manifest.get("wheel_sha256"):
        raise ValueError("downloaded setuptools wheel exceeds limit or does not match the published SHA-256")
    import io
    with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
        license_bytes = archive.read(manifest["license_archive_path"])
        if hashlib.sha256(license_bytes).hexdigest() != manifest["license_file_sha256"] or license_bytes != license_path.read_bytes():
            raise ValueError("setuptools wheel license does not match the bundled license asset")
        installed = {"/" + x["path"]: x for x in image_files if x["path"].endswith(".exe") and "/site-packages/setuptools/" in x["path"]}
        matched = []
        for filename, expected in manifest.get("launcher_files", {}).items():
            archive_bytes = archive.read(expected["archive_path"])
            if len(archive_bytes) != expected["size"] or hashlib.sha256(archive_bytes).hexdigest() != expected["sha256"]:
                raise ValueError(f"setuptools wheel launcher digest mismatch: {filename}")
            image_path = "/usr/local/lib/python3.14/site-packages/setuptools/" + filename
            image_file = installed.get(image_path)
            if not image_file or image_file["sha256"] != expected["sha256"]:
                raise ValueError(f"image setuptools launcher does not match exact wheel member: {image_path}")
            matched.append({"path": image_path, "sha256": expected["sha256"], "archive_path": expected["archive_path"]})
        if set(installed) != {x["path"] for x in matched}:
            raise ValueError("image setuptools launcher set differs from the exact wheel evidence manifest")
    target = dest / "SETUPTOOLS-84.0.0-MIT-LICENSE.txt"
    shutil.copyfile(license_path, target)
    disposition = {"package": "setuptools Windows launcher artifacts", "version": manifest["version"], "license_expression": manifest["license_expression"], "copyright": manifest["copyright"], "content_sha256": matched, "license_texts": [{"path": "third-party/notices/" + manifest["license_file"], "inventory_file": "notices/" + target.name, "sha256": manifest["license_file_sha256"]}], "source_material": [{"path": manifest["wheel_url"], "sha256": manifest["wheel_sha256"], "archive_member_paths": [x["archive_path"] for x in manifest["launcher_files"].values()]}], "obligation_resolution": manifest["source_resolution"], "provenance": {"wheel_url": url, "wheel_sha256": manifest["wheel_sha256"], "pypi_release_url": manifest["pypi_release_url"], "pypi_provenance": manifest["pypi_provenance"], "license_archive_path": manifest["license_archive_path"], "image_launcher_count": len(matched)}}
    return disposition, None


def verify_pip_launcher_evidence(image_files: list[dict], image_metadata: list[dict], dest: Path) -> dict:
    """Bind pip's vendored launcher bytes to its exact wheel and installed vendor manifest."""
    meta = json.loads((ROOT / "third-party/notices/VENDORED-LAUNCHERS.json").read_text())["pip_launchers"]
    matches = [x for x in image_metadata if x.get("name") == "pip" and x.get("version") == meta["version"]]
    if len(matches) != 1:
        raise ValueError("pip launcher evidence requires exactly one matching installed pip distribution version")
    with urllib.request.urlopen(meta["wheel_url"], timeout=30) as response:
        wheel = response.read(meta["wheel_size"] + 1)
    if len(wheel) != meta["wheel_size"] or hashlib.sha256(wheel).hexdigest() != meta["wheel_sha256"]:
        raise ValueError("pip wheel size or published SHA-256 mismatch")
    installed_vendor = [x for x in image_files if "/pip/_vendor/vendor.txt" in "/" + x.get("path", "")]
    if len(installed_vendor) != 1 or installed_vendor[0].get("sha256") != meta["vendor_manifest_sha256"]:
        raise ValueError("installed pip vendor.txt is missing, duplicated or differs from exact wheel member")
    vendor_data = (dest / installed_vendor[0]["file"]).read_bytes()
    if vendor_data != meta["vendor_manifest_text"].encode() and meta["vendor_manifest_text"].encode() not in vendor_data:
        raise ValueError("installed pip vendor.txt does not pin the expected distlib version")
    observed = {"/" + x["path"].lstrip("/"): x for x in image_files if x.get("path", "").endswith(".exe") and "/pip/_vendor/distlib/" in "/" + x.get("path", "")}
    expected_paths = {meta["launcher_root"] + name for name in meta["launcher_files"]}
    if set(observed) != expected_paths:
        raise ValueError("installed pip distlib PE launcher set differs from exact wheel members")
    import io
    with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
        vendor = archive.read(meta["vendor_manifest_archive_path"])
        if hashlib.sha256(vendor).hexdigest() != meta["vendor_manifest_sha256"]:
            raise ValueError("pip wheel vendor.txt member digest mismatch")
        license_bytes = archive.read(meta["license_archive_path"])
        license_path = ROOT / "third-party/notices" / meta["license_file"]
        if hashlib.sha256(license_bytes).hexdigest() != meta["license_file_sha256"] or license_path.read_bytes() != license_bytes:
            raise ValueError("pip wheel vendored license text differs from checked-in exact source text")
        with urllib.request.urlopen(meta["distlib_launcher_source_url"], timeout=30) as response:
            launcher_source = response.read(2_000_001)
        if len(launcher_source) > 2_000_000 or hashlib.sha256(launcher_source).hexdigest() != meta["distlib_launcher_source_sha256"]:
            raise ValueError("pinned distlib launcher source size or SHA-256 mismatch")
        source_text = launcher_source.decode("utf-8", errors="strict")
        header = re.search(r"/\*(.*?)\*/", source_text, re.DOTALL)
        source_notice = "\n".join(line.strip().removeprefix("*").strip() for line in header.group(1).splitlines()) if header else ""
        notice_path = ROOT / "third-party/notices/DISTLIB-LAUNCHER-BSD-2.txt"
        normalize = lambda value: re.sub(r"\s+", " ", value).strip()
        if not header or "Copyright (C) 2011-2022 Vinay Sajip" not in source_notice or normalize(notice_path.read_text()) not in normalize(source_notice):
            raise ValueError("exact distlib launcher source header does not support bundled copyright/license notice")
        source_target = dest / "source-material/distlib-0.4.2-PC-launcher.c"
        source_target.parent.mkdir(parents=True, exist_ok=True)
        source_target.write_bytes(launcher_source)
        wheel_target = dest / "source-material/pip-26.2.1-py3-none-any.whl"
        wheel_target.write_bytes(wheel)
        for name, expected in meta["launcher_files"].items():
            source = archive.read(expected["archive_path"])
            target = observed[meta["launcher_root"] + name]
            if len(source) != expected["size"] or hashlib.sha256(source).hexdigest() != expected["sha256"]:
                raise ValueError(f"pip wheel PE source member is corrupt: {name}")
            target_size = target.get("size")
            if target_size is None and target.get("file"):
                target_size = (dest / target["file"]).stat().st_size
            if target.get("sha256") != expected["sha256"] or target_size != expected["size"]:
                raise ValueError(f"installed pip PE target differs from exact wheel member: {name}")
    license_target = dest / "PIP-26.2.1-DISTLIB-LICENSE.txt"
    shutil.copyfile(license_path, license_target)
    return {"package": "pip vendored distlib Windows launchers", "version": "distlib 0.4.2 via pip 26.2.1", "license_expression": meta["license_expression"], "copyright": meta["copyright"], "content_sha256": [{"path": path, "sha256": observed[path]["sha256"], "size": meta["launcher_files"][Path(path).name]["size"], "source_archive_path": meta["launcher_files"][Path(path).name]["archive_path"], "source_sha256": meta["launcher_files"][Path(path).name]["sha256"], "source_size": meta["launcher_files"][Path(path).name]["size"]} for path in sorted(expected_paths)], "license_texts": [{"path": "third-party/notices/" + meta["license_file"], "inventory_file": "notices/" + license_target.name, "sha256": meta["license_file_sha256"]}], "source_material": [{"path": meta["wheel_url"], "sha256": meta["wheel_sha256"], "inventory_file": "notices/source-material/" + wheel_target.name}, {"path": meta["distlib_launcher_source_url"], "sha256": meta["distlib_launcher_source_sha256"], "inventory_file": "notices/source-material/" + source_target.name}], "obligation_resolution": "Exact pip wheel and installed vendor.txt both identify distlib 0.4.2; all six installed PE bytes match independently hashed wheel members. The exact distlib 0.4.2 launcher source header supplies the copyright and two binary/source redistribution conditions, which are checked against the bundled notice; the complete wheel license text is also retained verbatim.", "provenance": {"pip_version": meta["version"], "metadata_path": matches[0]["metadata_path"], "wheel_url": meta["wheel_url"], "wheel_sha256": meta["wheel_sha256"], "wheel_size": meta["wheel_size"], "distlib_launcher_source_url": meta["distlib_launcher_source_url"], "distlib_launcher_source_sha256": meta["distlib_launcher_source_sha256"], "vendor_manifest_path": installed_vendor[0]["path"], "vendor_manifest_sha256": installed_vendor[0]["sha256"], "pypi_release_url": meta["pypi_release_url"]}}


def verify_musl_license(source_evidence: dict, copied: dict[str, dict], source_image_id: str, dest: Path) -> dict:
    """Bind full tagged musl notice text to the copied Alpine runtime binaries."""
    asset_dir = ROOT / "third-party/notices"
    manifest = json.loads((asset_dir / "MUSL-LICENSE-EVIDENCE.json").read_text())
    license_path = asset_dir / manifest["license_file"]
    local_bytes = license_path.read_bytes()
    if hashlib.sha256(local_bytes).hexdigest() != manifest.get("license_file_sha256"):
        raise ValueError("musl license asset digest does not match its evidence manifest")
    with urllib.request.urlopen(manifest["raw_url"], timeout=30) as response:
        upstream_bytes = response.read(100_001)
    if len(upstream_bytes) > 100_000 or upstream_bytes != local_bytes:
        raise ValueError("downloaded version-tagged musl COPYRIGHT does not match the bundled notice")
    musl = source_evidence.get("musl", {})
    if musl.get("version") != "1.2.6-r2" or not any("MIT" == (x.get("spdx_expression") or x.get("value")) for x in musl.get("licenses", [])):
        raise ValueError("pinned Alpine source image does not match musl 1.2.6-r2 MIT evidence")
    paths = ("/opt/valkey/lib/ld-musl-x86_64.so.1", "/opt/valkey/lib/libc.musl-x86_64.so.1")
    if any(path not in copied for path in paths):
        raise ValueError("one or more copied musl runtime binaries lack content hashes")
    target = dest / manifest["license_file"]
    shutil.copyfile(license_path, target)
    return {"package": "musl copied Alpine runtime", "version": musl["version"], "license_expression": manifest["license_expression"], "copyright": manifest["copyright"], "content_sha256": [{"path": path, "sha256": copied[path]["sha256"]} for path in paths], "license_texts": [{"path": "third-party/notices/" + manifest["license_file"], "inventory_file": "notices/" + target.name, "sha256": manifest["license_file_sha256"]}], "source_material": [{"path": manifest["raw_url"], "sha256": manifest["license_file_sha256"]}], "obligation_resolution": "The full COPYRIGHT file from the musl 1.2.6 version tag is bundled verbatim and its digest is checked against the version-tagged source mirror at collection time. Alpine's pinned source-image SBOM identifies musl 1.2.6-r2 under MIT; both copied runtime binary hashes are retained. The recorded source caveat states that direct retrieval from the official musl release host was unavailable.", "provenance": {"source_image_id": source_image_id, "apk_package_metadata": musl, "tagged_source_url": manifest["source_url"], "official_upstream_release_url": manifest["upstream_release_url"], "source_note": manifest["source_note"]}}


def supplemental_python_licenses(image_metadata: list[dict], dest: Path) -> list[dict]:
    """Retain exact upstream texts omitted by the installed distributions."""
    pins = json.loads((ROOT / "third-party/notices/PYTHON-SUPPLEMENTAL-LICENSES.json").read_text())
    results = []
    for pin in pins:
        installed = [x for x in image_metadata if x.get("name") == pin["package"] and x.get("version") == pin["version"]]
        if not installed:
            continue
        text = ROOT / "third-party/notices" / pin["license_file"]
        if digest(text) != pin["license_sha256"]:
            raise ValueError("supplemental Python licence text differs from pinned source")
        with urllib.request.urlopen(pin["source_url"], timeout=30) as response:
            archive_bytes = response.read(pin["source_size"] + 1)
        if len(archive_bytes) != pin["source_size"] or hashlib.sha256(archive_bytes).hexdigest() != pin["source_sha256"]:
            raise ValueError("supplemental Python source archive identity mismatch")
        import io
        with tarfile.open(fileobj=io.BytesIO(archive_bytes)) as archive:
            stream = archive.extractfile(pin["source_member"])
            if stream is None or stream.read(1_000_001) != text.read_bytes():
                raise ValueError("supplemental Python licence differs from source archive member")
        source = dest / "source-material" / (pin["package"] + "-" + pin["version"] + ".tar.gz")
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(archive_bytes)
        target = dest / pin["license_file"]
        shutil.copyfile(text, target)
        results.append({"package": pin["package"], "version": pin["version"], "license_expression": pin["license_expression"],
            "copyright": pin["copyright"], "license_texts": [{"path": pin["license_file"], "inventory_file": "notices/" + target.name, "sha256": pin["license_sha256"]}],
            "source_material": [{"path": pin["source_url"], "inventory_file": "notices/source-material/" + source.name, "sha256": pin["source_sha256"]}],
            "obligation_resolution": "The complete MIT grant and copyright from the exact versioned source archive are retained verbatim; the installed distribution metadata identifies the same package and version.",
            "provenance": {"source_member": pin["source_member"], "installed_metadata": installed}})
    return results


def npm_license_texts(lock: dict, dest: Path) -> tuple[list[dict], list[dict]]:
    """Fetch production lock tarballs read-only and retain license files by integrity."""
    records, unresolved = [], []
    for key, value in sorted(lock.get("packages", {}).items()):
        if not key or value.get("dev"):
            continue
        name = key.removeprefix("node_modules/")
        version = value.get("version", "unknown")
        declared = value.get("license")
        resolved = value.get("resolved")
        sri = value.get("integrity", "")
        row = {"name": name, "version": version, "declared_license": declared}
        if not isinstance(declared, str) or not declared.strip() or not resolved or not sri.startswith("sha512-"):
            unresolved.append({**row, "reason": "missing declared license, resolved tarball, or sha512 integrity"})
            continue
        try:
            with urllib.request.urlopen(resolved, timeout=30) as response:
                blob = response.read(25_000_001)
            if len(blob) > 25_000_000:
                raise ValueError("npm package archive exceeds 25MB")
            expected = base64.b64decode(sri.removeprefix("sha512-"), validate=True)
            if hashlib.sha512(blob).digest() != expected:
                raise ValueError("npm package archive integrity mismatch")
            import io
            texts = []
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
                for member in archive:
                    p = PurePosixPath(member.name)
                    leaf = p.name.lower()
                    if member.isfile() and (leaf in {"license", "licence", "notice", "notices", "copying"} or leaf.startswith("license.")) and member.size <= 1_000_000:
                        stream = archive.extractfile(member)
                        if stream:
                            data = stream.read()
                            target = dest / "npm" / f"{hashlib.sha256((name + version + member.name).encode()).hexdigest()[:20]}-{p.name}"
                            target.parent.mkdir(parents=True, exist_ok=True)
                            target.write_bytes(data)
                            texts.append({"archive_path": member.name, "file": target.relative_to(dest.parent).as_posix(), "sha256": hashlib.sha256(data).hexdigest()})
            if not texts:
                unresolved.append({**row, "reason": "resolved package archive contains no license/notice text"})
            records.append({**row, "resolved": resolved, "integrity": sri, "license_files": texts})
        except Exception as exc:
            unresolved.append({**row, "reason": f"cannot verify/read resolved package contents: {exc}"})
    return records, unresolved


def acceptable_image(image: str) -> dict:
    if not IMAGE_RE.fullmatch(image):
        raise ValueError("--image must be an immutable sha256 image ID")
    info = json.loads(run(["docker", "image", "inspect", image]))[0]
    if info.get("Id") != image:
        raise ValueError("Docker returned a different image ID")
    if info.get("Os") != "linux" or info.get("Architecture") != "amd64":
        raise ValueError(f"expected linux/amd64, found {info.get('Os')}/{info.get('Architecture')}")
    return info


def admit_pinned_source_image(source_ref: str, source_id: str) -> dict:
    """Resolve the pinned registry manifest to an admitted local image record."""
    if not IMAGE_RE.fullmatch(source_id) or "@" not in source_ref or source_ref.rsplit("@", 1)[1] != source_id:
        raise ValueError("source image reference does not bind the supplied immutable digest")
    repository = source_ref.rsplit("@", 1)[0].rsplit("/", 1)
    repository = repository[0] + "/" + repository[1].split(":", 1)[0]
    inspect = ["docker", "image", "inspect", source_ref]
    try:
        raw = run(inspect)
    except subprocess.CalledProcessError:
        run(["docker", "pull", "--platform=linux/amd64", source_ref])
        raw = run(inspect)
    rows = json.loads(raw)
    if not isinstance(rows, list) or len(rows) != 1:
        raise ValueError("Docker did not resolve exactly one pinned source image")
    info = rows[0]
    if info.get("Os") != "linux" or info.get("Architecture") != "amd64":
        raise ValueError(f"expected pinned source linux/amd64, found {info.get('Os')}/{info.get('Architecture')}")
    if f"{repository}@{source_id}" not in (info.get("RepoDigests") or []):
        raise ValueError("resolved source image RepoDigests do not contain the pinned repository digest")
    if not IMAGE_RE.fullmatch(info.get("Id", "")):
        raise ValueError("Docker returned no immutable local source image ID")
    return {**info, "RegistryReference": source_ref, "RegistryDigest": source_id, "LocalImageId": info["Id"], "Platform": "linux/amd64"}


def remove_owned_export_container(cid: str, mounts: list[str], cleanup_log: list[dict], record_path: Path | None = None) -> None:
    command = ["docker", "rm", "--volumes", cid]
    cleanup = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    cleanup_log.append({"container_id": cid, "volume_ids": mounts, "command": command, "exit_code": cleanup.returncode, "stderr": cleanup.stderr.strip()})
    if record_path:
        record_path.parent.mkdir(parents=True, exist_ok=True)
        temp = record_path.with_suffix(record_path.suffix + ".tmp")
        temp.write_text(json.dumps(cleanup_log, indent=2, sort_keys=True) + "\n")
        temp.replace(record_path)
    if cleanup.returncode:
        raise RuntimeError(f"owned Docker export container/volume cleanup failed for {cid}: {cleanup.stderr.strip()}")


def extract_notice_files(image: str, dest: Path, cleanup_log: list[dict] | None = None, cleanup_record_path: Path | None = None) -> list[dict]:
    """Capture package copyright/license files from the flattened immutable image."""
    cid = run(["docker", "create", image]).strip()
    if not cid:
        raise ValueError("docker create returned no container ID")
    cleanup_log = cleanup_log if cleanup_log is not None else []
    mounts = []
    try:
        inspected = json.loads(run(["docker", "inspect", cid]))[0]
        mounts = [x.get("Name") for x in inspected.get("Mounts", []) if x.get("Type") == "volume" and x.get("Name")]
        proc = subprocess.Popen(["docker", "export", cid], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        found = []
        assert proc.stdout is not None
        with tarfile.open(fileobj=proc.stdout, mode="r|*") as archive:
            for member in archive:
                p = PurePosixPath(member.name)
                name = p.name.lower()
                dist_metadata = name == "metadata" and ".dist-info/" in str(p) and "site-packages/" in str(p)
                pip_vendor_manifest = str(p).endswith("/pip/_vendor/vendor.txt") and "site-packages/" in str(p)
                common_license = str(p).startswith("usr/share/common-licenses/")
                embedded_notice = str(p).startswith("usr/share/doc/volt/third-party/")
                launcher = name.endswith(".exe") and ("pip/_vendor/distlib/" in str(p) or "site-packages/setuptools/" in str(p))
                notice_name = launcher or name in {"copyright", "license", "licence", "notice", "notices", "copying"} or name.startswith(("license.", "licence.", "notice.", "copying.", "license-", "licence-", "notice-", "copying-")) or name.endswith((".license", ".licence"))
                copied_runtime = str(p) in {"opt/valkey/bin/valkey-server", "opt/valkey/bin/valkey-cli", "opt/valkey/lib/ld-musl-x86_64.so.1", "opt/valkey/lib/libc.musl-x86_64.so.1", "opt/valkey/lib/libssl.so.3", "opt/valkey/lib/libcrypto.so.3"}
                pygithub_source = str(p).startswith("usr/local/lib/python3.14/site-packages/github/") and p.suffix == ".py"
                if not member.isfile() or not (dist_metadata or pip_vendor_manifest or common_license or notice_name or copied_runtime or pygithub_source or embedded_notice):
                    continue
                if not (str(p).startswith(("usr/share/doc/", "usr/share/common-licenses/", "usr/local/lib/", "opt/uvm/", "opt/valkey/", "app/"))):
                    continue
                if member.size > 2_000_000 and not copied_runtime:
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    continue
                if copied_runtime:
                    h = hashlib.sha256()
                    size = 0
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        h.update(block); size += len(block)
                    found.append({"path": member.name, "sha256": h.hexdigest(), "size": size, "kind": "copied-runtime-binary"})
                    continue
                data = stream.read()
                if pygithub_source:
                    rel = str(p).split("site-packages/github/", 1)[1]
                    out_name = f"source-code/PyGithub-2.10.0/{rel}"
                    out = dest / out_name
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_bytes(data)
                    found.append({"path": member.name, "file": out_name, "sha256": hashlib.sha256(data).hexdigest(), "kind": "installed-python-source"})
                    continue
                out_name = f"image-files/{hashlib.sha256(member.name.encode()).hexdigest()[:16]}-{p.name}"
                out = dest / out_name
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(data)
                found.append({"path": member.name, "file": out_name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "kind": "embedded-notice-asset" if embedded_notice else "installed-vendor-manifest" if pip_vendor_manifest else "license-or-copyright"})
        stderr = proc.stderr.read() if proc.stderr else b""
        if proc.wait() != 0:
            raise RuntimeError(f"docker export failed: {stderr.decode(errors='replace')}")
        return found
    finally:
        remove_owned_export_container(cid, mounts, cleanup_log, cleanup_record_path)


def docker_export_file_hashes(image: str, paths: dict[str, str], cleanup_log: list[dict], cleanup_record_path: Path | None = None) -> dict[str, dict]:
    """Hash selected source-image paths, following in-image symlinks, and remove only our export container/volumes."""
    cid = run(["docker", "create", image]).strip()
    if not cid:
        raise ValueError("docker create returned no container ID for source evidence")
    mounts = []
    try:
        inspected = json.loads(run(["docker", "inspect", cid]))[0]
        mounts = [x.get("Name") for x in inspected.get("Mounts", []) if x.get("Type") == "volume" and x.get("Name")]
        proc = subprocess.Popen(["docker", "export", cid], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert proc.stdout is not None
        entries = {}
        with tarfile.open(fileobj=proc.stdout, mode="r|*") as archive:
            wanted = {p.lstrip("/"): out for p, out in paths.items()}
            source_names = ("valkey-server", "valkey-cli", "ld-musl-x86_64.so.1", "libc.musl-x86_64.so.1", "libssl.so", "libcrypto.so")
            for member in archive:
                name = member.name.removeprefix("./").rstrip("/")
                if name in wanted or (member.isfile() and PurePosixPath(name).name.startswith(source_names)):
                    stream = archive.extractfile(member) if member.isfile() else None
                    entries[name] = (member, stream.read() if stream else None)
        stderr = proc.stderr.read() if proc.stderr else b""
        if proc.wait() != 0:
            raise RuntimeError(f"docker export failed: {stderr.decode(errors='replace')}")
        result = {}
        for original, output in paths.items():
            key = original.lstrip("/")
            visited = set()
            while key in entries and (entries[key][0].issym() or entries[key][0].islnk()):
                if key in visited:
                    raise ValueError(f"source image symlink cycle at /{key}")
                visited.add(key)
                member = entries[key][0]
                key = posixpath.normpath(member.linkname.lstrip("/") if member.linkname.startswith("/") or member.islnk() else posixpath.join(posixpath.dirname(key), member.linkname))
            if key not in entries or entries[key][1] is None:
                raise ValueError(f"source image file missing or not regular after symlink resolution: {original}")
            data = entries[key][1]
            h = hashlib.sha256(data); size = len(data)
            result[output] = {"source_path": original, "resolved_source_path": "/" + key, "sha256": h.hexdigest(), "size": size}
        return result
    finally:
        remove_owned_export_container(cid, mounts, cleanup_log, cleanup_record_path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image", required=True, help="immutable local Docker image ID sha256:<64 hex>; must be linux/amd64")
    ap.add_argument("--output", required=True, type=Path, help="new or empty output directory; binds all output to this image ID and platform")
    ap.add_argument("--syft", type=Path, help="reviewed Syft 1.55.0 binary; if omitted, resolve from PATH and verify version")
    ap.add_argument("--debian-dispositions", type=Path, help="JSON array of evidence-backed per-source-package/version disposition records")
    ap.add_argument("--debian-developer-keyring", type=Path, default=Path("/usr/share/keyrings/debian-keyring.pgp"), help="Debian developer keyring used only to verify maintainer-signed .dsc files")
    args = ap.parse_args()
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        ap.error("output directory must be empty")
    out.mkdir(parents=True, exist_ok=True)
    image = acceptable_image(args.image)
    syft = str(args.syft or shutil.which("syft") or "")
    if not syft:
        ap.error("Syft binary missing; download the pinned linux/amd64 release and verify tools.lock SHA256")
    version = run([syft, "version"])
    if "1.55.0" not in version:
        ap.error(f"expected Syft 1.55.0, got {version.strip()}")
    run([syft, "scan", "--quiet", "--platform", "linux/amd64", f"docker:{args.image}", "-o", f"syft-json={out / 'sbom.syft.json'}"])
    run([syft, "scan", "--quiet", "--platform", "linux/amd64", f"docker:{args.image}", "-o", f"spdx-json={out / 'sbom.spdx.json'}"])
    dockerfile_text = (ROOT / "Dockerfile.g7").read_text()
    source_match = VALKEY_SOURCE_RE.search(dockerfile_text)
    if not source_match:
        ap.error("Dockerfile.g7 VALKEY_IMAGE must remain pinned by immutable digest")
    source_registry_digest = source_match.group(1)
    source_ref = re.search(r"^ARG VALKEY_IMAGE=([^\n]+)$", dockerfile_text, re.MULTILINE).group(1)
    # Explicitly admit the registry-pinned source into this daemon; BuildKit
    # cache presence is not treated as a Docker image record.
    source_image = admit_pinned_source_image(source_ref, source_registry_digest)
    source_image_id = source_image["LocalImageId"]
    run([syft, "scan", "--quiet", "--platform", "linux/amd64", f"docker:{source_image_id}", "-o", f"syft-json={out / 'sbom.valkey-source.syft.json'}"])
    source_packages = packages_from_sbom(out / "sbom.valkey-source.syft.json")
    source_package_rows = [p for p in source_packages if p.get("name") in {"valkey", "musl", "libssl3", "libcrypto3", "openssl"}]
    source_licence_map = {p.get("name"): {"version": p.get("version"), "licenses": license_records(p), "source_url": (p.get("metadata") or {}).get("url"), "source_commit": (p.get("metadata") or {}).get("gitCommitOfApkPort"), "package_files": (p.get("metadata") or {}).get("files", [])} for p in source_package_rows}
    inv = out / "notices"
    inv.mkdir()
    # Preserve the approved project notice text verbatim, plus package metadata
    # captured from the actual final image. Unknowns remain explicit findings.
    (inv / "VOLT-THIRD-PARTY-NOTICES.md").write_bytes((ROOT / "THIRD-PARTY-NOTICES.md").read_bytes())
    (inv / "VOLT-LICENSE.txt").write_bytes((ROOT / "LICENSE").read_bytes())
    refs = inv / "reference-sources"
    refs.mkdir()
    source_files = ["Dockerfile.g7", "docker/g7/versions.lock", "pyproject.toml", "uv.lock", "ui/package.json", "ui/package-lock.json", "THIRD-PARTY-NOTICES.md", "LICENSE", "tools/notices/collect.py", "tools/notices/verify.py", "tools/notices/tools.lock", "tests/notices/test_verify.py", "docs/third-party-notices.md"]
    source_files.extend(p.relative_to(ROOT).as_posix() for p in (ROOT / "third-party/notices").rglob("*") if p.is_file())
    source_files = sorted(set(source_files))
    source_digests = []
    for rel in source_files:
        src = ROOT / rel
        target = refs / rel.replace("/", "__")
        shutil.copyfile(src, target)
        source_digests.append({"path": rel, "sha256": digest(src), "inventory_file": target.relative_to(out).as_posix()})
    unresolved = []
    docker_cleanup = []
    cleanup_record_path = inv / "docker-cleanup-records.json"
    image_files = extract_notice_files(args.image, inv, docker_cleanup, cleanup_record_path)
    source_paths = {
        "/usr/local/bin/valkey-server": "/opt/valkey/bin/valkey-server",
        "/usr/local/bin/valkey-cli": "/opt/valkey/bin/valkey-cli",
        "/lib/ld-musl-x86_64.so.1": "/opt/valkey/lib/ld-musl-x86_64.so.1",
        "/lib/libc.musl-x86_64.so.1": "/opt/valkey/lib/libc.musl-x86_64.so.1",
        "/usr/lib/libssl.so.3": "/opt/valkey/lib/libssl.so.3",
        "/usr/lib/libcrypto.so.3": "/opt/valkey/lib/libcrypto.so.3",
    }
    source_file_hashes = docker_export_file_hashes(source_image_id, source_paths, docker_cleanup, cleanup_record_path)
    target_file_hashes = {"/" + x["path"]: x for x in image_files if x.get("kind") == "copied-runtime-binary"}
    for target_path, source_row in source_file_hashes.items():
        target_row = target_file_hashes.get(target_path)
        if not target_row or (target_row["sha256"], target_row["size"]) != (source_row["sha256"], source_row["size"]):
            unresolved.append({"name": "copied runtime binary provenance", "version": target_path, "reason": "source-image bytes do not match the copied final-image target", "source": source_row, "target": target_row})
    (inv / "copied-source-file-hashes.json").write_text(json.dumps(source_file_hashes, indent=2, sort_keys=True) + "\n")
    packages = packages_from_sbom(out / "sbom.syft.json")
    embedded_expected = {"usr/share/doc/volt/third-party/THIRD-PARTY-NOTICES.md": digest(ROOT / "THIRD-PARTY-NOTICES.md"), "usr/share/doc/volt/third-party/LICENSE": digest(ROOT / "LICENSE")}
    for asset in (ROOT / "third-party/notices").rglob("*"):
        if asset.is_file():
            embedded_expected["usr/share/doc/volt/third-party/source/" + asset.relative_to(ROOT / "third-party/notices").as_posix()] = digest(asset)
    embedded_actual = {x["path"]: x["sha256"] for x in image_files if x.get("kind") == "embedded-notice-asset"}
    embedded_rows = [{"path": path, "expected_sha256": expected, "image_sha256": embedded_actual.get(path), "status": "verified" if embedded_actual.get(path) == expected else "missing-or-mismatched"} for path, expected in sorted(embedded_expected.items())]
    (inv / "embedded-notice-assets.json").write_text(json.dumps(embedded_rows, indent=2, sort_keys=True) + "\n")
    if any(x["status"] != "verified" for x in embedded_rows):
        unresolved.append({"name": "embedded third-party notice assets", "version": "Dockerfile.g7", "license_expression": None, "evidence": embedded_rows, "reason": "The immutable image does not contain every checked-in curated license and notice asset at the Dockerfile destination with the expected content digest.", "action_choices": ["build the candidate from the current Dockerfile.g7 so it embeds the reviewed assets, then rerun collection on that immutable image ID"]})
    covered = []
    package_findings = {}
    image_metadata = {}
    for item in image_files:
        image_path = item["path"]
        if not image_path.endswith(".dist-info/METADATA"):
            continue
        metadata = Parser().parsestr((inv / item["file"]).read_text(errors="replace"))
        dist_dir = image_path.split(".dist-info/", 1)[0].rsplit("/", 1)[-1]
        dist_name = re.sub(r"[-_.]+\d.*$", "", dist_dir).lower().replace("_", "-")
        hints = sorted({str(value).strip() for value in (metadata.get("License-Expression"), metadata.get("License")) if value and str(value).strip() and str(value).strip().lower() not in {"unknown", "see license"}})
        classifiers = [v for v in metadata.get_all("Classifier", []) if v.startswith("License ::")]
        prefix = image_path.rsplit("/", 1)[0] + "/"
        siblings = [x for x in image_files if x["path"].startswith(prefix) and x["path"] != image_path and any(part in x["path"].lower() for part in ("license", "licence", "notice", "copying"))]
        site_root = "/" + image_path.split("/site-packages/", 1)[0] + "/site-packages"
        image_metadata["|".join((dist_name, str(metadata.get("Version") or ""), site_root))] = {"name": dist_name, "install_location": site_root, "distribution": metadata.get("Name", dist_dir), "version": metadata.get("Version"), "metadata_path": image_path, "metadata_sha256": item["sha256"], "author": metadata.get("Author-email") or metadata.get("Author"), "license_hints": hints, "license_classifiers": classifiers, "license_files": siblings}
    (inv / "python-distribution-license-evidence.json").write_text(json.dumps(image_metadata, indent=2, sort_keys=True) + "\n")
    pygithub_source = [x for x in image_files if x.get("kind") == "installed-python-source" and "/site-packages/github/" in x["path"]]
    def exact_metadata(name: str, version: str | None = None, package: dict | None = None):
        normalized = name.lower().replace("_", "-")
        candidates = [row for row in image_metadata.values() if row.get("name") == normalized and (version is None or row.get("version") == version)]
        locations = [x.get("path", "") for x in (package or {}).get("locations", [])]
        roots = {x.split("/site-packages/", 1)[0] + "/site-packages" for x in locations if "/site-packages/" in x}
        if roots:
            candidates = [x for x in candidates if x.get("install_location") in roots]
        return candidates[0] if len(candidates) == 1 else None
    pygithub_meta = exact_metadata("pygithub", "2.10.0")
    pygithub_licences = pygithub_meta.get("license_files", []) if pygithub_meta else []
    pygithub_disposition = supplemental_python_licenses(list(image_metadata.values()), inv)
    if pygithub_meta and len(pygithub_licences) == 2 and pygithub_source:
        lesser = next((x for x in pygithub_licences if x["path"].endswith("COPYING.LESSER")), None)
        copying = next((x for x in pygithub_licences if x["path"].endswith("/COPYING")), None)
        if lesser and copying:
            init_source = next((x for x in pygithub_source if x["path"].endswith("/github/__init__.py")), None)
            init_text = (inv / init_source["file"]).read_text(errors="replace") if init_source else ""
            grant = pygithub_license_expression(init_text)
            if not init_source or grant != "LGPL-3.0-or-later":
                unresolved.append({"name": "PyGithub", "version": "2.10.0", "reason": "captured package source does not contain the expected LGPL v3-or-later grant"})
            else:
                pygithub_disposition.append({"package": "PyGithub", "version": "2.10.0", "package_metadata_sha256": pygithub_meta["metadata_sha256"], "content_sha256": sorted({x["sha256"] for x in pygithub_source}), "source_material": [{"path": x["path"], "sha256": x["sha256"], "inventory_file": "notices/" + x["file"]} for x in pygithub_source], "license_expression": grant, "copyright": ["Vincent Jacques (upstream package Author-email)", "Free Software Foundation, Inc. (license texts)"], "license_texts": [{"path": x["path"], "inventory_file": "notices/" + x["file"], "sha256": x["sha256"]} for x in (copying, lesser)], "obligation_resolution": "Exact installed source header grants GNU LGPL version 3 or any later version. The installed 2.10.0 Python files and GPL COPYING/LGPL COPYING.LESSER texts are included with per-file SHA-256.", "provenance": {"source_header_path": init_source["path"], "source_header_sha256": init_source["sha256"], "source_header_grant": "LGPL version 3 or any later version", "metadata_source_url": "https://github.com/PyGithub/PyGithub/blob/5cdf6ab/pyproject.toml", "upstream_documentation_url": "https://github.com/PyGithub/PyGithub/blob/5cdf6ab/doc/introduction.rst", "distribution_metadata_path": pygithub_meta["metadata_path"]}})
    # Include the common Apache license and the checked-in UI license metadata
    # in the image-bound evidence. The source URL identifies the exact OpenSSL
    # release whose package expression is present in the source-image SBOM.
    (inv / "OPENSSL-APACHE-2.0.txt").write_bytes((ROOT / "third-party/notices/OPENSSL-APACHE-2.0.txt").read_bytes())
    (inv / "DISTLIB-LAUNCHER-BSD-2.txt").write_bytes((ROOT / "third-party/notices/DISTLIB-LAUNCHER-BSD-2.txt").read_bytes())
    (inv / "MUSL-LICENSE-EVIDENCE.json").write_bytes((ROOT / "third-party/notices/MUSL-LICENSE-EVIDENCE.json").read_bytes())
    setuptools_disposition, setuptools_error = verify_setuptools_launcher_evidence(image_files, inv)
    if setuptools_error:
        unresolved.append(setuptools_error)
    # Include all image packages; license text discovery evidence is attached
    # separately. SBOM-reported license identifiers are never treated as text.
    for p in packages:
        name = p.get("name") or p.get("SPDXID") or "<unnamed>"
        version_id = p.get("version") or p.get("versionInfo") or "unknown"
        if p.get("foundBy") == "pe-binary-package-cataloger":
            paths = [x.get("path", "") for x in p.get("locations", [])]
            if any("pip/_vendor/distlib/" in x or "site-packages/setuptools/" in x for x in paths):
                covered.append({"name": name, "version": version_id, "classification": "vendored Windows launcher artifact; license attributed through containing distribution evidence"})
                continue
        license_evidence = license_records(p)
        licenses = sorted({x["spdx_expression"] or x["value"] for x in license_evidence if x["spdx_expression"] or x["value"]})
        row = {"name": name, "version": version_id, "licenses": licenses}
        identity = {"type": p.get("type"), "name": name, "version": version_id, "purl": p.get("purl"), "locations": sorted({x.get("path", "") for x in p.get("locations", [])})}
        row["identity"] = identity
        evidence_key = json.dumps(identity, sort_keys=True)
        if str(name).lower() == "python" and re.fullmatch(r"3\.14\.\d+", str(version_id)):
            py_license = next((x for x in image_files if x["path"] == "usr/local/lib/python3.14/LICENSE.txt"), None)
            if py_license and "Python Software Foundation License" in (inv / py_license["file"]).read_text(errors="replace"):
                covered.append({**row, "resolution": f"exact CPython {version_id} LICENSE.txt retained with source path and digest"})
                package_findings[evidence_key] = {**row, "license_evidence": [{"value": "PSF-2.0", "source_path": py_license["path"], "source_sha256": py_license["sha256"]}]}
                pygithub_disposition.append({"package": "CPython", "version": version_id, "license_expression": "PSF-2.0", "copyright": "Python Software Foundation and Python contributors, as stated in the captured LICENSE.txt", "license_texts": [{"path": py_license["path"], "inventory_file": "notices/" + py_license["file"], "sha256": py_license["sha256"]}], "obligation_resolution": "The complete versioned upstream license text shipped in the image is retained with source path and content hash; no source-offer duty is indicated by this PSF license text.", "provenance": {"runtime_image": args.image, "installed_path": py_license["path"]}})
                continue
        if str(name).lower() == "valkey" and str(version_id) == "9.1.2" and source_licence_map.get("valkey", {}).get("version") == "9.1.2":
            notice_text = (inv / "VOLT-THIRD-PARTY-NOTICES.md").read_text()
            present_binary_paths = {"/" + x["path"] for x in image_files if x.get("kind") == "copied-runtime-binary"}
            if all(pth in present_binary_paths for pth in EXPECTED_COPIED_ASSETS) and "Valkey contributors" in notice_text and "Redis Ltd." in notice_text:
                covered.append({**row, "resolution": "source-image version and exact copied binary hashes bound to the included Valkey 9.1.2 BSD-3-Clause notice"})
                package_findings[evidence_key] = {**row, "license_evidence": [{"value": "BSD-3-Clause", "source_path": "THIRD-PARTY-NOTICES.md", "source_sha256": digest(ROOT / "THIRD-PARTY-NOTICES.md"), "source_image_id": source_image_id}]}
                pygithub_disposition.append({"package": "Valkey", "version": version_id, "license_expression": "BSD-3-Clause", "copyright": ["Valkey contributors", "Redis Ltd."], "content_sha256": [{"path": x["path"], "sha256": x["sha256"]} for x in image_files if x.get("kind") == "copied-runtime-binary" and "valkey/bin/" in x["path"]], "license_texts": [{"path": "THIRD-PARTY-NOTICES.md#Valkey-9.1.2-COPYING", "inventory_file": "notices/VOLT-THIRD-PARTY-NOTICES.md", "sha256": digest(inv / "VOLT-THIRD-PARTY-NOTICES.md")}], "obligation_resolution": "The exact pinned source image SBOM identifies Valkey 9.1.2; both copied executable digests are captured; the complete BSD-3-Clause COPYING text and both copyright holders are in the image-bound notice file.", "provenance": {"source_image_id": source_image_id, "upstream_source": "https://github.com/valkey-io/valkey/tree/9.1.2", "binary_paths": [x["path"] for x in image_files if x.get("kind") == "copied-runtime-binary" and "valkey/bin/" in x["path"]]}})
                continue
        evidence = exact_metadata(str(name), str(version_id), p) if p.get("type") == "python" else None
        effective = [x for x in licenses if str(x).strip().upper() not in {"NOASSERTION", "UNKNOWN", "NONE", ""}] or (evidence or {}).get("license_hints", []) or [x.removeprefix("License :: OSI Approved :: ") for x in (evidence or {}).get("license_classifiers", [])]
        metadata_texts = [{"path": x.get("path"), "sha256": x.get("sha256"), "metadata_path": (evidence or {}).get("metadata_path"), "version": (evidence or {}).get("version"), "install_location": (evidence or {}).get("install_location")} for x in (evidence or {}).get("license_files", [])]
        row["metadata_license_hints"] = (evidence or {}).get("license_hints", [])
        row["metadata_license_texts"] = metadata_texts
        package_findings[evidence_key] = {**row, "license_evidence": license_evidence, "metadata_license_hints": (evidence or {}).get("license_hints", []), "metadata_license_classifiers": (evidence or {}).get("license_classifiers", []), "metadata_license_texts": metadata_texts, "metadata_license_identity": {"name": (evidence or {}).get("name"), "version": (evidence or {}).get("version"), "install_location": (evidence or {}).get("install_location"), "metadata_path": (evidence or {}).get("metadata_path"), "metadata_sha256": (evidence or {}).get("metadata_sha256")}}
        effective = [x for x in effective if str(x).strip().upper() not in {"NOASSERTION", "UNKNOWN", "NONE", ""}]
        if not effective:
            unresolved.append({**row, "reason": "no license expression discovered by Syft or installed distribution metadata"})
        elif not licenses and not (evidence or {}).get("license_files"):
            unresolved.append({**row, "reason": "installed distribution provides a license hint but no paired license/notice text file"})
        else:
            covered.append(row)
    copied_rows = [x for x in image_files if x.get("kind") == "copied-runtime-binary"]
    copied_by_path = {"/" + x["path"]: x for x in copied_rows}
    openssl_text = inv / "OPENSSL-APACHE-2.0.txt"
    openssl_groups = [source_licence_map.get(n, {}) for n in ("libcrypto3", "libssl3")]
    if all(x.get("version") == "3.5.8-r0" and any("Apache-2.0" in (l.get("spdx_expression") or l.get("value", "")) for l in x.get("licenses", [])) for x in openssl_groups) and all(p in copied_by_path for p in ("/opt/valkey/lib/libssl.so.3", "/opt/valkey/lib/libcrypto.so.3")):
        pygithub_disposition.append({"package": "OpenSSL Alpine runtime libraries", "version": "3.5.8-r0", "license_expression": "Apache-2.0", "copyright": "As included in the upstream OpenSSL 3.5.8 source/license; Alpine package metadata identifies origin package openssl.", "content_sha256": [{"path": p, "sha256": copied_by_path[p]["sha256"]} for p in ("/opt/valkey/lib/libssl.so.3", "/opt/valkey/lib/libcrypto.so.3")], "license_texts": [{"path": "third-party/notices/OPENSSL-APACHE-2.0.txt", "inventory_file": "notices/OPENSSL-APACHE-2.0.txt", "sha256": digest(openssl_text)}], "obligation_resolution": "Exact pinned Alpine source-image SBOM records libssl3 and libcrypto3 version 3.5.8-r0 with Apache-2.0. The corresponding copied runtime library digests and complete Apache-2.0 text are retained. Upstream OpenSSL states 3.0 and later use Apache-2.0.", "provenance": {"source_image_id": source_image_id, "upstream_license_url": "https://raw.githubusercontent.com/openssl/openssl/openssl-3.5.8/LICENSE.txt", "upstream_release_url": "https://openssl-library.org/source/"}})
    musl_evidence = source_licence_map.get("musl", {})
    musl_disposition = None
    if musl_evidence:
        try:
            musl_disposition = verify_musl_license(source_licence_map, copied_by_path, source_image_id, inv)
            pygithub_disposition.append(musl_disposition)
        except (OSError, ValueError, KeyError, urllib.error.URLError) as exc:
            unresolved.append({"name": "musl copied Alpine runtime", "version": musl_evidence.get("version"), "license_expression": "MIT", "evidence": {"source_image_id": source_image_id, "apk_metadata": musl_evidence, "copied_binary_sha256": [{"path": x["path"], "sha256": x["sha256"]} for x in copied_by_path.values() if "musl" in x["path"]]}, "reason": f"musl 1.2.6 tagged COPYRIGHT evidence could not be validated: {exc}", "action_choices": ["restore access to the version-tagged musl 1.2.6 COPYRIGHT source and rerun collection", "or include matching checksum-verified Alpine source package license text"]})
    # npm lock includes production and development records; include only packages
    # represented by runtime bundles where the lock records production status.
    lock = json.loads((ROOT / "ui/package-lock.json").read_text())
    ui_packages = []
    ui_packages, ui_unresolved = npm_license_texts(lock, inv)
    unresolved.extend(ui_unresolved)
    (inv / "ui-production-lock-licenses.json").write_text(json.dumps(ui_packages, indent=2, sort_keys=True) + "\n")
    bundled_ui = verify_bundled_ui_assets(lock)
    unresolved.extend(bundled_ui["unresolved"])
    (inv / "ui-bundled-license-assets.json").write_text(json.dumps(bundled_ui, indent=2, sort_keys=True) + "\n")
    # The copied Valkey/musl/OpenSSL files are explicitly tracked as provenance
    # even when the package manager cataloger has no ownership record.
    binary_rows = {"/" + x["path"]: x for x in image_files if x.get("kind") == "copied-runtime-binary"}
    expected_binary_paths = EXPECTED_COPIED_ASSETS
    provenance = {"dockerfile": "Dockerfile.g7", "lock": "docker/g7/versions.lock", "source_image_id": source_image_id, "source_image_platform": f"{source_image['Os']}/{source_image['Architecture']}", "source_image_sbom": "sbom.valkey-source.syft.json", "copied_assets": [{"path": p, "sha256": binary_rows[p]["sha256"], "size": binary_rows[p]["size"], "source_package": "valkey" if "valkey/bin/" in p else "musl" if "musl" in p else "openssl"} for p in expected_binary_paths if p in binary_rows], "missing_assets": [p for p in expected_binary_paths if p not in binary_rows], "source_image_package_evidence": source_licence_map, "resolved_license_dispositions": [x for x in pygithub_disposition if x["package"] in {"Valkey", "OpenSSL Alpine runtime libraries", "musl copied Alpine runtime"}], "unresolved_license_obligations": [x for x in unresolved if x.get("name") == "musl copied Alpine runtime"]}
    (inv / "copied-binary-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    (inv / "image-license-files.json").write_text(json.dumps(image_files, indent=2, sort_keys=True) + "\n")
    # Classify PE launcher catalog entries separately; the digest-bound file
    # evidence is retained in image-license-files.json and launcher inventory.
    launchers = []
    launcher_paths = {"/" + x["path"]: x for x in image_files if x["path"].endswith(".exe") and ("pip/_vendor/distlib/" in x["path"] or "site-packages/setuptools/" in x["path"])}
    vendored_meta = json.loads((ROOT / "third-party/notices/VENDORED-LAUNCHERS.json").read_text())
    distlib_license_path = ROOT / "third-party/notices" / vendored_meta["distlib"]["license_file"]
    distlib_license_sha = digest(distlib_license_path)
    if distlib_license_sha != vendored_meta["distlib"]["license_file_sha256"]:
        raise ValueError("checked-in distlib launcher license asset digest does not match its manifest")
    for p in packages:
        if p.get("foundBy") != "pe-binary-package-cataloger":
            continue
        for loc in p.get("locations", []):
            item = launcher_paths.get(loc.get("path", ""))
            if item:
                is_pip_distlib = "/pip/_vendor/distlib/" in loc["path"]
                launchers.append({"catalog_name": p.get("name"), "catalog_version": p.get("version"), "path": loc["path"], "sha256": item["sha256"], "inventory_file": "notices/" + item["file"], "classification": "vendored Windows launcher artifact; not a Linux runtime distribution", "license_expression": vendored_meta["distlib"]["license_expression"] if is_pip_distlib else None, "license_file": "notices/" + vendored_meta["distlib"]["license_file"] if is_pip_distlib else None, "license_file_sha256": distlib_license_sha if is_pip_distlib else None, "source_evidence": vendored_meta["distlib"]["source_urls"] if is_pip_distlib else [], "license_evidence": license_records(p)})
    launchers = deduplicate_findings(launchers)
    unresolved = [x for x in unresolved if not (x.get("name") in {"Simple Launcher", "cli", "cli-32", "cli-64", "cli-arm64", "gui", "gui-32", "gui-64", "gui-arm64"} and x.get("reason", "").startswith("no license expression"))]
    setuptools_launchers = [x for x in launchers if "/site-packages/setuptools/" in x["path"]]
    if setuptools_launchers and setuptools_disposition:
        for launcher in setuptools_launchers:
            launcher["license_expression"] = "MIT"
            launcher["license_file"] = "notices/SETUPTOOLS-84.0.0-MIT-LICENSE.txt"
            launcher["license_file_sha256"] = setuptools_disposition["license_texts"][0]["sha256"]
        if (exact_metadata("setuptools", "84.0.0") or {}).get("version") != "84.0.0":
            unresolved.append({"name": "setuptools Windows launcher artifacts", "version": (exact_metadata("setuptools") or {}).get("version", "unknown"), "license_expression": "MIT", "reason": "The image distribution version differs from the exact wheel version that matches the checked-in launcher evidence."})
        else:
            pygithub_disposition.append(setuptools_disposition)
    pip_launchers = [x for x in launchers if "/pip/_vendor/distlib/" in x["path"]]
    if pip_launchers:
        try:
            pip_meta = exact_metadata("pip", "26.2.1")
            if not pip_meta: raise ValueError("exact installed pip metadata/version/location not found")
            pip_disposition = verify_pip_launcher_evidence(image_files, [pip_meta], inv)
            pygithub_disposition.append(pip_disposition)
        except (OSError, ValueError, KeyError, urllib.error.URLError) as exc:
            unresolved.append({"name": "pip vendored distlib Windows launchers", "version": "pip 26.2.1", "reason": str(exc)})
    (inv / "launcher-artifacts.json").write_text(json.dumps(launchers, indent=2, sort_keys=True) + "\n")
    (inv / "package-license-dispositions.json").write_text(json.dumps(pygithub_disposition, indent=2, sort_keys=True) + "\n")
    source_groups = debian_source_groups(packages, image_files, out)
    (inv / "debian-source-packages.json").write_text(json.dumps(source_groups, indent=2, sort_keys=True) + "\n")
    disposition_rows = json.loads(args.debian_dispositions.read_text()) if args.debian_dispositions else []
    if not isinstance(disposition_rows, list):
        raise ValueError("--debian-dispositions must contain a JSON array")
    dispositions = {}
    for row in disposition_rows:
        key = (row.get("source_package"), row.get("source_version"))
        if not all(key) or key in dispositions:
            raise ValueError("Debian source disposition has missing or duplicate package/version identity")
        dispositions[key] = row
    known = {(x["source_package"], x["source_version"]) for x in source_groups}
    if set(dispositions) - known:
        raise ValueError("Debian source disposition contains stale package/version identities")
    copy_disposition_evidence(dispositions, out, args.debian_dispositions.resolve().parent if args.debian_dispositions else None)
    for disposition in dispositions.values():
        if disposition.get("decision") != "source-bundle":
            continue
        bundle = disposition["source_bundle"]
        dsc = out / bundle["signed_dsc_path"]
        if bundle.get("index_authentication"):
            # The verifier independently validates the archive signature, exact
            # signed index, package identity, .dsc and complete source checksum set.
            continue
        if not args.debian_developer_keyring.is_file():
            raise ValueError("Debian developer keyring is required to verify maintainer-signed source .dsc")
        if digest(args.debian_developer_keyring) != DEBIAN_DEVELOPER_KEYRING_SHA256:
            raise ValueError("Debian developer keyring does not match the reviewed tools.lock trust-root digest")
        result = subprocess.run(["gpgv", "--keyring", str(args.debian_developer_keyring.resolve()), str(dsc)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            raise ValueError(f"Debian source .dsc signature verification failed: {result.stderr.strip()}")
        keyring_target = out / "notices/debian-source-material/debian-developer-keyring.pgp"
        keyring_target.parent.mkdir(parents=True, exist_ok=True)
        if not keyring_target.exists():
            try: os.link(args.debian_developer_keyring.resolve(), keyring_target)
            except OSError: shutil.copyfile(args.debian_developer_keyring, keyring_target)
        bundle["signature_verification"] = {"keyring_path": keyring_target.relative_to(out).as_posix(), "keyring_sha256": digest(keyring_target), "gpgv_version": run(["gpgv", "--version"]).splitlines()[0], "result": "valid", "status_output": result.stderr.strip()}
    source_offer_candidates = debian_source_offer_candidates(source_groups, dispositions, out)
    for candidate in source_offer_candidates:
        if candidate["status"] != "resolved":
            unresolved.append({"name": candidate["source_package"], "version": candidate["source_version"], "reason": "Debian source-package file-stanza disposition is pending", "license_declarations": candidate["license_declarations"], "copyright_files": candidate["copyright_files"], "action_choices": candidate["action_choices"]})
    (inv / "debian-source-candidates.json").write_text(json.dumps(source_offer_candidates, indent=2, sort_keys=True) + "\n")
    unresolved = deduplicate_findings(unresolved)
    provenance["source_files"] = source_file_hashes
    provenance["source_distribution_admission"] = {"reference": source_ref, "registry_digest": source_registry_digest, "local_image_id": source_image_id, "platform": source_image["Platform"], "repo_digests": source_image.get("RepoDigests", [])}
    (inv / "copied-binary-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    report = {"schema": "volt-notice-inventory/v1", "source_revision": run(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).strip(), "image_id": args.image, "platform": f"{image['Os']}/{image['Architecture']}", "syft_version": "1.55.0", "syft_binary_sha256": digest(Path(syft)), "source_files": source_digests, "package_count": len(packages), "packages_with_license_metadata": len(covered), "runtime_ui_packages": len(ui_packages), "bundled_ui_license_package_count": bundled_ui['package_count'], "package_disposition_count": len(pygithub_disposition), "package_license_evidence": sorted(package_findings.values(), key=lambda x:(x['name'],x['version'])), "unresolved": unresolved, "debian_source_package_count": len(source_groups), "debian_source_candidate_count": len(source_offer_candidates), "embedded_notice_asset_count": len(embedded_rows), "launcher_artifact_count": len(launchers), "limitations": ["SBOM license expressions and image copyright files are evidence, not legal determinations.", "Debian source references are grouped by exact source package/version and remain blocking until a matching archive, written offer or exact source-file exclusion is evidenced.", "SPDX OR alternatives are preserved; AND components remain conjunctive. A disposition is bound to exact package/version and inventory evidence.", "Copied Valkey, musl and OpenSSL asset bytes are independently compared with the explicitly admitted pinned source image."], "files": []}
    for path in sorted(x for x in out.rglob("*") if x.is_file()):
        if path.name == "notice-manifest.json":
            continue
        report["files"].append({"path": path.relative_to(out).as_posix(), "sha256": digest(path), "size": path.stat().st_size})
    (out / "notice-manifest.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if not unresolved:
        run([sys.executable, str(ROOT / "tools/notices/verify.py"), "--directory", str(out), "--image", args.image])
    print(json.dumps({"image_id": args.image, "platform": report["platform"], "package_count": len(packages), "unresolved_count": len(unresolved), "output": str(out)}, sort_keys=True))
    return 0 if not unresolved else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"notice collection failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
