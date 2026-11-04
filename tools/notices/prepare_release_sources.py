#!/usr/bin/env python3
"""Acquire the catalogued public source closure into a fresh preparation directory."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

# Direct ``python3 tools/notices/prepare_release_sources.py`` is the documented
# CI entrypoint. Python otherwise puts only tools/notices on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

CATALOG = Path(__file__).with_name("debian-source-catalog.json")
DEBIAN_SNAPSHOT = "https://snapshot.debian.org"
DEBIAN_KEYRING_SHA256 = "81e08f47b0dd8a563a2742ad90878ccefe53aa0728b095acbea3efda84381ea9"
FETCH_ATTEMPTS = 4
FETCH_BACKOFF_SECONDS = (1, 2, 4)
RETRYABLE_HTTP_STATUS = {429, 503, 504}


class TransientFetchError(ValueError):
    """A public source transport failed after its bounded transient retries."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_public_url(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urllib.parse.urlunsplit((parts.scheme, host, parts.path, "", ""))


def _transient_transport_error(exc: BaseException) -> bool:
    cause = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(cause, socket.gaierror):
        return cause.errno == socket.EAI_AGAIN
    return isinstance(cause, (TimeoutError, ConnectionError,
                              http.client.RemoteDisconnected, http.client.IncompleteRead))


def _transport_error_label(exc: BaseException) -> str:
    cause = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(cause, socket.gaierror) and cause.errno == socket.EAI_AGAIN:
        return "dns-temporary"
    return type(cause).__name__


def _fetch_route(url: str) -> str:
    host = urllib.parse.urlsplit(url).hostname
    if host == "snapshot.debian.org":
        return "debian-snapshot"
    if host == "deb.debian.org":
        return "debian-canonical"
    return "public-source"


def validate_canonical_fallback_url(url: str, filename: str) -> str:
    parts = urllib.parse.urlsplit(url)
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid canonical Debian fallback URL port") from exc
    path = urllib.parse.unquote(parts.path)
    segments = PurePosixPath(path).parts
    package = filename.split("_", 1)[0]
    canonical_names = {filename}
    if "_" in filename and ":" in filename.split("_", 1)[1]:
        stem, remainder = filename.split("_", 1)
        canonical_names.add(f"{stem}_{remainder.split(':', 1)[1]}")
    pool_prefix = f"lib{package[3]}" if package.startswith("lib") and len(package) > 3 else package[:1]
    allowed_paths = {
        ("debian", "pool", "main", pool_prefix, package),
        ("debian-security", "pool", "updates", "main", pool_prefix, package),
    }
    path_parts = tuple(segments[1:-1])
    if (parts.scheme != "https" or parts.hostname != "deb.debian.org"
            or parts.username is not None or parts.password is not None or port not in (None, 443)
            or parts.query or parts.fragment or "%" in parts.path
            or path_parts not in allowed_paths or ".." in segments
            or PurePosixPath(path).name not in canonical_names):
        raise ValueError("canonical source fallback must be an exact HTTPS deb.debian.org pool URL for the catalogued source filename")
    return url


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "VOLT-notice-source-preparer/1.0"})
    safe_url = _safe_public_url(url)
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                if _fetch_route(url) == "debian-canonical":
                    final = urllib.parse.urlsplit(response.geturl() if hasattr(response, "geturl") else url)
                    if final.scheme != "https" or final.hostname != "deb.debian.org":
                        raise ValueError("canonical Debian source redirected outside the approved HTTPS host")
                data = response.read()
                if attempt > 1:
                    status = getattr(response, "status", None) or getattr(response, "code", 200)
                    print(f"NOTICE_SOURCE_FETCH route={_fetch_route(url)} attempt={attempt}/{FETCH_ATTEMPTS} outcome=success "
                          f"status={status} bytes={len(data)} url={safe_url}", file=sys.stderr)
                return data
        except urllib.error.HTTPError as exc:
            if exc.code not in RETRYABLE_HTTP_STATUS:
                raise
            reason = f"http-{exc.code}"
            exc.close()
        except (urllib.error.URLError, TimeoutError, ConnectionError,
                http.client.HTTPException) as exc:
            if not _transient_transport_error(exc):
                raise
            reason = _transport_error_label(exc)

        outcome = "exhausted" if attempt == FETCH_ATTEMPTS else "retry"
        print(f"NOTICE_SOURCE_FETCH route={_fetch_route(url)} attempt={attempt}/{FETCH_ATTEMPTS} outcome={outcome} "
              f"reason={reason} url={safe_url}", file=sys.stderr)
        if attempt == FETCH_ATTEMPTS:
            raise TransientFetchError(f"public source fetch exhausted transient retries: {reason} {safe_url}")
        time.sleep(FETCH_BACKOFF_SECONDS[attempt - 1])
    raise AssertionError("unreachable fetch retry state")


def release_sha256_row(cleartext: str, relative_path: str) -> tuple[str, int]:
    sections = cleartext.split("SHA256:", 1)
    if len(sections) != 2:
        raise ValueError("signed InRelease has no SHA256 section")
    section = re.split(r"(?m)^[A-Z][A-Za-z0-9-]*:\s*$", sections[1])[0]
    rows = [line.split() for line in section.splitlines() if line.split() and line.split()[-1] == relative_path]
    if len(rows) != 1 or len(rows[0]) != 3 or not re.fullmatch(r"[0-9a-f]{64}", rows[0][0]) or not rows[0][1].isdigit():
        raise ValueError(f"signed InRelease lacks one complete SHA-256/size row for {relative_path}")
    return rows[0][0], int(rows[0][1])


def write_verified(path: Path, data: bytes, expected: str, label: str) -> None:
    if digest(data) != expected:
        raise ValueError(f"{label}: downloaded SHA-256 differs from reviewed catalog")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def extract_deb_member(deb: bytes, package_path: Path, member_path: str, expected_sha: str, label: str) -> Path:
    package_path.parent.mkdir(parents=True, exist_ok=True)
    package_path.write_bytes(deb)
    target = package_path.parent / (package_path.stem + "-extract")
    checked = subprocess.run(["dpkg-deb", "-x", str(package_path), str(target)], capture_output=True, text=True)
    if checked.returncode:
        raise ValueError(f"{label}: public package extraction failed: {checked.stderr.strip()}")
    member = target / member_path
    if not member.is_file() or digest(member.read_bytes()) != expected_sha:
        raise ValueError(f"{label}: extracted member differs from pinned SHA-256")
    return member


def prepare_trust_inputs(root: Path, catalog: dict) -> tuple[Path, dict[str, Path]]:
    material = root / "debian-source-material"
    material.mkdir(parents=True, exist_ok=True)
    dev = catalog["debian_developer_keyring"]
    dev_deb = fetch(dev["package_url"])
    if len(dev_deb) != dev["package_size"] or digest(dev_deb) != dev["package_sha256"]:
        raise ValueError("public Debian developer-keyring package size/SHA-256 mismatch")
    dev_member = extract_deb_member(dev_deb, material / "debian-keyring.deb",
                                    "usr/share/keyrings/debian-keyring.pgp", dev["sha256"],
                                    "Debian developer keyring")
    dev_target = root / "debian-developer-keyring.gpg"
    shutil.copyfile(dev_member, dev_target)

    archive = catalog["trust_inputs"]["debian_archive"]
    archive_deb = fetch(archive["package_url"])
    if len(archive_deb) != archive["package_size"] or digest(archive_deb) != archive["package_sha256"]:
        raise ValueError("public Debian archive-keyring package size/SHA-256 mismatch")
    archive_member = extract_deb_member(archive_deb, material / "debian-archive-keyring.deb",
                                        "usr/share/keyrings/debian-archive-keyring.pgp",
                                        archive["keyring_sha256"], "Debian archive keyring")
    archive_target = material / "debian-archive-keyring.pgp"
    shutil.copyfile(archive_member, archive_target)

    pgdg = catalog["trust_inputs"]["postgresql_pgdg"]
    armored = fetch(pgdg["key_url"])
    if len(armored) != pgdg["key_size"] or digest(armored) != pgdg["key_sha256"]:
        raise ValueError("public PGDG key input size/SHA-256 mismatch")
    armored_path = material / "ACCC4CF8.asc"
    armored_path.write_bytes(armored)
    pgdg_target = material / "postgresql-pgdg.gpg"
    converted = subprocess.run(["gpg", "--batch", "--yes", "--dearmor", "--output", str(pgdg_target), str(armored_path)], capture_output=True, text=True)
    if converted.returncode or digest(pgdg_target.read_bytes()) != pgdg["keyring_sha256"]:
        raise ValueError("public PGDG key does not reproduce the pinned keyring")
    listed = subprocess.run(["gpg", "--batch", "--with-colons", "--show-keys", str(pgdg_target)], capture_output=True, text=True)
    fingerprints = [line.split(":")[9].upper() for line in listed.stdout.splitlines() if line.startswith("fpr:")]
    if pgdg["signer_fingerprint"] not in fingerprints:
        raise ValueError("public PGDG key does not contain the pinned signer fingerprint")
    return dev_target, {"debian-trixie-archive": archive_target, "postgresql-pgdg": pgdg_target}


def signed_repository_source_index(root: Path, entry: dict, keyring: Path, trust: dict) -> tuple[dict, dict]:
    package, version = entry["source_package"], entry["source_version"]
    trust_root = entry["index_authentication"]["trust_root"]
    trust_key = {"debian-trixie-archive": "debian_archive", "postgresql-pgdg": "postgresql_pgdg"}.get(trust_root, trust_root)
    meta = trust[trust_key]
    base = meta["repository_url"].rstrip("/") + "/"
    material = root / "debian-source-material"
    suite = "trixie-pgdg" if trust_root == "postgresql-pgdg" else "trixie"
    index_relative = "main/source/Sources.gz" if trust_root == "postgresql-pgdg" else "main/source/Sources.xz"
    inrelease_data = fetch(base + f"dists/{suite}/InRelease")
    prefix = "pgdg-trixie-pgdg" if trust_root == "postgresql-pgdg" else "debian-trixie"
    inrelease = material / f"{prefix}-InRelease"
    inrelease.write_bytes(inrelease_data)
    checked = subprocess.run(["gpgv", "--keyring", str(keyring), str(inrelease)], capture_output=True, text=True)
    signers = [meta["signer_fingerprint"]] if "signer_fingerprint" in meta else meta["signer_fingerprints"]
    if checked.returncode or not any(fp in checked.stderr.upper() for fp in signers):
        raise ValueError(f"current {trust_root} InRelease signature or pinned signer validation failed")
    release = inrelease_data.decode(errors="replace")
    if not release.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        raise ValueError("current PGDG InRelease is not clear-signed")
    clear = release.split("\n\n", 1)[1].split("\n-----BEGIN PGP SIGNATURE-----", 1)[0]
    index_digest, index_size = release_sha256_row(clear, index_relative)
    index_data = fetch(base + f"dists/{suite}/{index_relative}")
    index = material / f"{prefix}-Sources.{index_relative.rsplit('.', 1)[1]}"
    index.write_bytes(index_data)
    if len(index_data) != index_size or digest(index_data) != index_digest:
        raise ValueError(f"current {trust_root} Sources index differs from signed InRelease")
    from tools.notices.verify import parse_deb822_index, parse_sha256_members
    matches = [row for row in parse_deb822_index(index) if row.get("Package") == package and row.get("Version") == version]
    if len(matches) != 1:
        raise ValueError(f"current {trust_root} Sources index lacks one exact {package}@{version} stanza")
    source = matches[0]
    if not source.get("Directory", "").startswith("pool/"):
        raise ValueError(f"{trust_root} Sources stanza has an invalid source directory")
    source_members = parse_sha256_members(source.get("Checksums-Sha256") or "")
    dsc_names = [name for name in source_members if name.endswith(".dsc")]
    catalog_members = {row["filename"]: row["sha256"] for row in entry["source_files"]}
    source_archives = {name: checksum for name, (checksum, _size) in source_members.items() if not name.endswith(".dsc")}
    if len(dsc_names) != 1 or source_archives != catalog_members:
        raise ValueError(f"current {trust_root} stanza source members drift for {package}@{version}")
    dsc_name = dsc_names[0]
    dsc_data = fetch(base + source["Directory"].rstrip("/") + "/" + dsc_name)
    dsc_digest, dsc_size = source_members[dsc_name]
    if len(dsc_data) != dsc_size or digest(dsc_data) != dsc_digest or dsc_digest != entry["dsc_sha256"]:
        raise ValueError(f"current {trust_root} descriptor differs from pinned {package}@{version}")
    dsc_path = material / f"{package}-{version}" / dsc_name
    dsc_path.parent.mkdir(parents=True, exist_ok=True)
    dsc_path.write_bytes(dsc_data)
    evidence = {
        "trust_root": trust_root, "trust_route": "signed-repository-index",
        "inrelease_path": inrelease.relative_to(root).as_posix(), "inrelease_sha256": digest(inrelease.read_bytes()),
        "index_path": index.relative_to(root).as_posix(), "index_sha256": digest(index_data),
        "index_size": index.stat().st_size, "index_release_path": index_relative,
        "keyring_path": keyring.relative_to(root).as_posix(), "keyring_sha256": digest(keyring.read_bytes()),
    }
    return {"directory": source["Directory"], "members": source_members, "dsc_name": dsc_name,
            "dsc_path": dsc_path}, evidence


def snapshot_files(package: str, version: str) -> dict[str, tuple[str, int]]:
    encoded = urllib.parse.quote(version, safe="")
    raw = fetch(f"{DEBIAN_SNAPSHOT}/mr/package/{urllib.parse.quote(package, safe='')}/{encoded}/srcfiles")
    index = json.loads(raw)
    if index.get("package") != package or index.get("version") != version:
        raise ValueError(f"snapshot locator returned a different identity for {package}@{version}")
    found: dict[str, tuple[str, int]] = {}
    for item in index.get("result", []):
        blob = item.get("hash", "")
        if not re.fullmatch(r"[0-9a-f]{40}", blob):
            raise ValueError(f"invalid snapshot locator for {package}@{version}")
        info = json.loads(fetch(f"{DEBIAN_SNAPSHOT}/mr/file/{blob}/info"))
        locations = [x for x in info.get("result", []) if x.get("archive_name") in {"debian", "debian-security"}]
        if not locations:
            continue
        names = {(x.get("name"), x.get("size")) for x in locations}
        if len(names) != 1:
            raise ValueError(f"conflicting public locator metadata for {package}@{version}")
        name, size = next(iter(names))
        if not isinstance(name, str) or not isinstance(size, int) or size < 0:
            raise ValueError(f"invalid public locator metadata for {package}@{version}")
        if name in found and found[name] != (blob, size):
            raise ValueError(f"duplicate source filename {name} for {package}@{version}")
        found[name] = (blob, size)
    return found


def catalog_matches(catalog: dict, candidates: list[dict]) -> None:
    indexed = {(x.get("source_package"), x.get("source_version")): x for x in catalog["groups"]}
    observed = {(x.get("source_package"), x.get("source_version")): x for x in candidates}
    if len(observed) != len(candidates) or set(observed) != set(indexed):
        raise ValueError("notice inventory source package/version set differs from reviewed catalog")
    for key, entry in indexed.items():
        row = observed[key]
        if row.get("license_declarations") != entry["license_declarations"]:
            raise ValueError(f"catalog drift in license declarations for {key[0]}@{key[1]}")
        if row.get("file_stanzas") != entry["file_stanzas"]:
            raise ValueError(f"catalog drift in copyright stanza bindings for {key[0]}@{key[1]}")
        actual_copyright = sorted((x.get("path"), x.get("sha256")) for x in row.get("copyright_files", []))
        expected_copyright = sorted((x["path"], x["sha256"]) for x in entry["copyright_files"])
        if actual_copyright != expected_copyright:
            raise ValueError(f"catalog drift in copyright files for {key[0]}@{key[1]}")


def parse_sha1_members(value: str) -> dict[str, tuple[str, int]]:
    members = {}
    for line in value.splitlines():
        parts = line.split()
        if len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{40}", parts[0]) or not parts[1].isdigit() or not parts[2]:
            raise ValueError("malformed SHA-1 member row")
        if parts[2] in members:
            raise ValueError("duplicate SHA-1 member filename")
        members[parts[2]] = (parts[0], int(parts[1]))
    if not members:
        raise ValueError("empty SHA-1 member list")
    return members


def acquire_group(entry: dict, root: Path, keyring_path: Path, repository_keyrings: dict[str, Path], trust: dict) -> dict:
    package, version = entry["source_package"], entry["source_version"]
    material = root / "debian-source-material"
    target_dir = material / f"{package}-{version}"
    target_dir.mkdir(parents=True, exist_ok=True)
    signed_index = entry.get("index_authentication")
    is_repository_signed = bool(signed_index)
    immutable_dsc_sha1 = entry.get("immutable_dsc_sha1")
    if immutable_dsc_sha1 is not None and not re.fullmatch(r"[0-9a-f]{40}", immutable_dsc_sha1):
        raise ValueError(f"{package}@{version}: invalid immutable .dsc SHA-1 locator")
    repository_source = repository_evidence = None
    if is_repository_signed:
        repository_source, repository_evidence = signed_repository_source_index(
            root, entry, repository_keyrings[signed_index["trust_root"]], trust)
        locators = {}
    elif immutable_dsc_sha1:
        locators = {}
    else:
        locators = snapshot_files(package, version)
    names = [x["filename"] for x in entry["source_files"]]
    if len(names) != len(set(names)) or (not (is_repository_signed or immutable_dsc_sha1) and not set(names).issubset(locators)):
        raise ValueError(f"snapshot file set does not contain every catalogued member for {package}@{version}")

    immutable_members = None

    def get_blob(name: str) -> bytes:
        if is_repository_signed:
            if name not in repository_source["members"]:
                raise ValueError(f"current signed index omits {package}@{version} {name}")
            checksum, size = repository_source["members"][name]
            trust_key = {"debian-trixie-archive": "debian_archive", "postgresql-pgdg": "postgresql_pgdg"}.get(signed_index["trust_root"], signed_index["trust_root"])
            repository_url = trust[trust_key]["repository_url"].rstrip("/")
            data = fetch(repository_url + "/" + repository_source["directory"].rstrip("/") + "/" + name)
            if len(data) != size or digest(data) != checksum:
                raise ValueError(f"{package}@{version} {name}: current signed member SHA-256/size mismatch")
            return data
        if immutable_dsc_sha1:
            if immutable_members is None or name not in immutable_members:
                raise ValueError(f"{package}@{version}: signed immutable .dsc omits {name}")
            blob, size = immutable_members[name]
            source_row = next(row for row in entry["source_files"] if row["filename"] == name)
            fallback_url = source_row.get("fallback_url")
            if fallback_url is not None:
                fallback_url = validate_canonical_fallback_url(fallback_url, name)
            try:
                data = fetch(f"{DEBIAN_SNAPSHOT}/file/{blob}")
            except TransientFetchError:
                if fallback_url is None:
                    raise
                print(f"NOTICE_SOURCE_FALLBACK package={package} version={version} filename={name} "
                      "from=debian-snapshot to=debian-canonical reason=transient-exhaustion",
                      file=sys.stderr)
                data = fetch(fallback_url)
            if len(data) != size or hashlib.sha1(data).hexdigest() != blob:
                raise ValueError(f"{package}@{version} {name}: immutable locator SHA-1/size mismatch")
            return data
        blob, size = locators[name]
        data = fetch(f"{DEBIAN_SNAPSHOT}/file/{blob}")
        if len(data) != size:
            raise ValueError(f"{package}@{version} {name}: locator size mismatch")
        if hashlib.sha1(data).hexdigest() != blob:
            raise ValueError(f"{package}@{version} {name}: public locator digest mismatch")
        return data

    dsc_names = ([repository_source["dsc_name"]] if is_repository_signed else
                 [f"{package}_{version}.dsc"] if immutable_dsc_sha1 else
                 [name for name in locators if name.endswith(".dsc")])
    if not dsc_names:
        raise ValueError(f"exact .dsc locator is missing for {package}@{version}")
    if is_repository_signed:
        dsc_matches = [(repository_source["dsc_name"], repository_source["dsc_path"].read_bytes())]
    elif immutable_dsc_sha1:
        descriptor_fallback_url = entry.get("immutable_dsc_fallback_url")
        if descriptor_fallback_url is not None:
            descriptor_fallback_url = validate_canonical_fallback_url(
                descriptor_fallback_url, f"{package}_{version}.dsc")
        try:
            immutable_dsc = fetch(f"{DEBIAN_SNAPSHOT}/file/{immutable_dsc_sha1}")
        except TransientFetchError:
            if descriptor_fallback_url is None:
                raise
            print(f"NOTICE_SOURCE_FALLBACK package={package} version={version} filename={package}_{version}.dsc "
                  "from=debian-snapshot to=debian-canonical reason=transient-exhaustion",
                  file=sys.stderr)
            immutable_dsc = fetch(descriptor_fallback_url)
        if hashlib.sha1(immutable_dsc).hexdigest() != immutable_dsc_sha1:
            raise ValueError(f"{package}@{version}: immutable .dsc locator SHA-1 mismatch")
        dsc_matches = [(dsc_names[0], immutable_dsc)]
    else:
        dsc_matches = [(name, get_blob(name)) for name in dsc_names]
    dsc_matches = [(name, data) for name, data in dsc_matches if digest(data) == entry["dsc_sha256"]]
    if len(dsc_matches) != 1:
        raise ValueError(f"{package}@{version}: exact .dsc differs from catalog")
    dsc_filename, dsc_data = dsc_matches[0]
    dsc_path = target_dir / dsc_filename
    dsc_path.write_bytes(dsc_data)
    if not signed_index:
        checked = subprocess.run(["gpgv", "--keyring", str(keyring_path), str(dsc_path)], capture_output=True, text=True)
        if checked.returncode:
            raise ValueError(f"{package}@{version}: maintainer signature check failed: {checked.stderr.strip()}")
    from tools.notices.verify import parse_dsc_control
    dsc_fields = parse_dsc_control(dsc_path)
    if dsc_fields.get("Source", "").split()[0] != package or dsc_fields.get("Version") != version:
        raise ValueError(f"{package}@{version}: signed .dsc identity differs from catalog")
    if immutable_dsc_sha1:
        immutable_members = parse_sha1_members(dsc_fields.get("Checksums-Sha1") or "")
    dsc_members = {}
    for line in (dsc_fields.get("Checksums-Sha256") or "").splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[2] in dsc_members:
            raise ValueError(f"{package}@{version}: malformed or duplicate .dsc SHA-256 member")
        if not re.fullmatch(r"[0-9a-f]{64}", parts[0]) or not parts[1].isdigit():
            raise ValueError(f"{package}@{version}: invalid signed .dsc SHA-256 row")
        dsc_members[parts[2]] = (parts[0], int(parts[1]))
    catalog_members = {row["filename"]: row["sha256"] for row in entry["source_files"]}
    if (not dsc_members or set(dsc_members) != set(catalog_members)
            or any(dsc_members[name][0] != checksum for name, checksum in catalog_members.items())):
        raise ValueError(f"{package}@{version}: catalog source-member set differs from signed .dsc")
    if immutable_dsc_sha1 and set(immutable_members) != set(catalog_members):
        raise ValueError(f"{package}@{version}: immutable .dsc SHA-1 member set differs from catalog")

    files = []
    for row in entry["source_files"]:
        data = get_blob(row["filename"])
        signed_digest, signed_size = dsc_members[row["filename"]]
        if digest(data) != signed_digest or len(data) != signed_size:
            raise ValueError(f"{package}@{version} {row['filename']}: bytes differ from signed SHA-256/size")
        path = target_dir / row["filename"]
        path.write_bytes(data)
        files.append({"filename": row["filename"], "path": path.relative_to(root).as_posix(), "sha256": row["sha256"]})

    bundle = {"source_package": package, "source_version": version,
              "filename": files[0]["filename"], "path": files[0]["path"], "sha256": files[0]["sha256"],
              "files": files, "signed_dsc_path": dsc_path.relative_to(root).as_posix(),
              "signed_dsc_sha256": entry["dsc_sha256"]}
    if signed_index:
        evidence = dict(repository_evidence)
        bundle["signed_dsc_filename"] = dsc_filename
        bundle["index_authentication"] = evidence
        from tools.notices.verify import verify_signed_index_bundle
        errors = verify_signed_index_bundle(bundle, root, package, version)
        if errors:
            raise ValueError("; ".join(errors))
    return bundle


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new preparation output directory")
    args = parser.parse_args()
    root = args.output.resolve()
    try:
        catalog = json.loads(CATALOG.read_text())
        if catalog.get("schema") != "volt-debian-source-catalog/v1":
            raise ValueError("unsupported source catalog schema")
        root.mkdir(parents=True, exist_ok=False)
        keyring_path, repository_keyrings = prepare_trust_inputs(root, catalog)
        dispositions = []
        for entry in catalog["groups"]:
            package, version = entry["source_package"], entry["source_version"]
            bundle = acquire_group(entry, root, keyring_path, repository_keyrings, catalog["trust_inputs"])
            resolutions = [{"spdx_expression": x["spdx_expression"], "copyright_sha256": x["copyright_sha256"],
                            "status": "resolved", "resolution": f"Exact {package} {version} source files match the reviewed catalog and were authenticated by the catalogued trust route."}
                           for x in entry["license_declarations"]]
            stanzas = [{"copyright_path": x["copyright_path"], "copyright_sha256": x["copyright_sha256"],
                        "stanza_sha256": x["stanza_sha256"], "files_patterns": x["files_patterns"],
                        "action": "source-bundle", "status": "resolved", "source_package": package,
                        "source_version": version, "source_bundle_sha256": bundle["sha256"]}
                       for x in entry["file_stanzas"]]
            dispositions.append({"source_package": package, "source_version": version, "status": "resolved",
                                 "decision": "source-bundle", "declaration_resolutions": resolutions,
                                 "file_stanza_resolutions": stanzas, "source_bundle": bundle})
        result = root / "debian-source-dispositions.json"
        result.write_text(json.dumps(dispositions, indent=2, sort_keys=True) + "\n")
        print(f"Prepared {len(dispositions)} exact Debian source groups at {result}")
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, urllib.error.URLError, subprocess.SubprocessError) as exc:
        print(f"FAIL: release source preparation: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
