#!/usr/bin/env python3
"""Create and verify a signed, safely loadable offline VOLT release archive."""
from __future__ import annotations

import argparse
import base64
import hashlib
import gzip
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zlib

import provenance as provenance_validator

EXPECTED_VERSION = "0.1.0-rc.2"
SUPPORTED_ARCHIVE_VERSIONS = {"0.1.0-rc.1", EXPECTED_VERSION}
COMPOSE_BUNDLE_FILES = ("VERSION", "README.md", "backup-restore.md", "compose.yaml", "demo.yaml",
                        "compose.env.example", "oidc.example.json", "setup.py")
EXPECTED_PLATFORM = "linux/amd64"
EXPECTED_IDENTITY = "https://github.com/njvenis/volt/.github/workflows/release.yml@refs/heads/main"
EXPECTED_ISSUER = "https://token.actions.githubusercontent.com"
MAX_UNPACKED = 20 * 1024**3


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def verify_compose_bundle(bundle: Path, version: str, registry_digest: str,
                          source_root: Path | None = None) -> None:
    expected_ref = f"ghcr.io/njvenis/volt@{registry_digest}"
    if not re.fullmatch(r"ghcr\.io/njvenis/volt@sha256:[0-9a-f]{64}", expected_ref):
        raise ValueError("Compose bundle requires the exact published VOLT image digest")
    checksum_path = bundle.with_suffix(bundle.suffix + ".sha256")
    if not checksum_path.is_file() or checksum_path.read_text() != f"{sha(bundle)}  {bundle.name}\n":
        raise ValueError("Compose bundle checksum does not match its archive")
    try:
        with tarfile.open(bundle, "r:gz") as tf:
            members = tf.getmembers()
            names = [member.name for member in members]
            root = f"volt-compose-{version}"
            expected_names = {f"{root}/{name}" for name in (*COMPOSE_BUNDLE_FILES, "manifest.json")}
            if (len(names) != len(set(names)) or set(names) != expected_names
                    or any(not member.isfile() for member in members)):
                raise ValueError("Compose bundle closed inventory or archive member types are invalid")
            contents = {}
            for member in members:
                stream = tf.extractfile(member)
                if stream is None:
                    raise ValueError("Compose bundle member cannot be read")
                contents[PurePosixPath(member.name).name] = stream.read()
    except (OSError, tarfile.TarError) as exc:
        raise ValueError("Compose bundle is not a readable gzip tar archive") from exc
    try:
        metadata = json.loads(contents["manifest.json"])
    except (KeyError, json.JSONDecodeError) as exc:
        raise ValueError("Compose bundle manifest is missing or malformed") from exc
    actual_hashes = {name: hashlib.sha256(contents[name]).hexdigest() for name in COMPOSE_BUNDLE_FILES}
    if (not isinstance(metadata, dict) or metadata.get("format_version") != 1
            or metadata.get("bundle_version") != version or metadata.get("release_image") != expected_ref
            or metadata.get("files") != actual_hashes or contents["VERSION"].decode().strip() != version
            or expected_ref.encode() not in contents["README.md"]):
        raise ValueError("Compose bundle version, image reference or signed file hashes are inconsistent")
    if source_root is not None:
        compose_source = source_root / "deploy" / "compose"
        for name in COMPOSE_BUNDLE_FILES:
            original = (compose_source / name).read_bytes()
            expected = original.replace(b"VOLT_RELEASE_IMAGE_REFERENCE", expected_ref.encode())
            if contents[name] != expected:
                raise ValueError(f"Compose bundle source file differs from signed source, including digest substitution: {name}")


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def build_manifest(directory: Path, version: str, source_sha: str, image_id: str,
                   platform: str, signer_identity: str, issuer: str, registry_digest: str) -> dict:
    if version not in SUPPORTED_ARCHIVE_VERSIONS:
        raise ValueError("unsupported VOLT release archive version")
    if platform != EXPECTED_PLATFORM:
        raise ValueError("only linux/amd64 is approved")
    if len(source_sha) != 40 or any(c not in "0123456789abcdef" for c in source_sha):
        raise ValueError("source revision must be a full lowercase Git SHA-1")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise ValueError("image identity must be an immutable sha256 ID")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", registry_digest):
        raise ValueError("published OCI registry digest must be immutable")
    source_snapshot = "sha256:" + sha(directory / "source.tar")
    required = ["image.tar", "source.tar", "sbom.syft.json", "sbom.spdx.json",
                "release-scan.json", "VERIFY.txt", "provenance.json", "registry-digest.txt", "notice-manifest.json",
                "source.bundle"]
    if version == EXPECTED_VERSION:
        required += ["volt-compose.tar.gz", "volt-compose.tar.gz.sha256"]
    else:
        required += ["tools-g7-local-preview.py", "launcher-guide.txt"]
    for name in required:
        if not (directory / name).is_file():
            raise ValueError(f"required offline release file missing: {name}")
    notice_files = list((directory / "notices").rglob("*")) if (directory / "notices").is_dir() else []
    if not any(p.is_file() for p in notice_files):
        raise ValueError("generated notice files are missing")
    inventory = {}
    for path in sorted(p for p in directory.rglob("*") if p.is_file() and p.relative_to(directory).as_posix() not in {"manifest.json", "SHA256SUMS", "signature.bundle"}):
        rel = path.relative_to(directory).as_posix()
        if rel.startswith("../"):
            raise ValueError("invalid package path")
        inventory[rel] = sha(path)
    if signer_identity != EXPECTED_IDENTITY or issuer != EXPECTED_ISSUER:
        raise ValueError("release signer must be the main-branch publication workflow with GitHub OIDC")
    if version == EXPECTED_VERSION:
        verify_compose_bundle(directory / "volt-compose.tar.gz", version, registry_digest)
    manifest = {
        "schema": "volt-offline-release/v1", "version": version,
        "source_commit": source_sha, "image_id": image_id, "platform": platform,
        "source_snapshot": source_snapshot,
        "registry_digest": registry_digest,
        "signer_identity": signer_identity, "oidc_issuer": issuer,
        "files": inventory,
    }
    identity = validate_docker_archive(directory / "image.tar", manifest)
    manifest["image_index_id"] = identity["image_index_id"]
    manifest["image_config_id"] = identity["image_config_id"]
    manifest["platform_manifest_digest"] = identity["platform_manifest_digest"]
    return manifest


def _member_bytes(tf: tarfile.TarFile, members: dict, name: str) -> bytes:
    member = members.get(name)
    if member is None or not member.isfile():
        raise ValueError(f"image archive object is missing: {name}")
    stream = tf.extractfile(member)
    if stream is None:
        raise ValueError(f"image archive object cannot be read: {name}")
    return stream.read()


def _descriptor(tf: tarfile.TarFile, members: dict, descriptor: object, *, allowed_media: set[str]) -> tuple[str, bytes]:
    if not isinstance(descriptor, dict):
        raise ValueError("OCI image descriptor is malformed")
    digest, size, media = descriptor.get("digest"), descriptor.get("size"), descriptor.get("mediaType")
    match = re.fullmatch(r"sha256:([0-9a-f]{64})", digest or "") if isinstance(digest, str) else None
    if not match or not isinstance(size, int) or size < 0 or media not in allowed_media:
        raise ValueError("OCI descriptor digest, size or media type is invalid")
    name = "blobs/sha256/" + match.group(1)
    data = _member_bytes(tf, members, name)
    if len(data) != size or hashlib.sha256(data).hexdigest() != match.group(1):
        raise ValueError(f"OCI descriptor size or digest mismatch: {name}")
    return media, data


def _uncompressed_layer_digest(data: bytes, media: str | None) -> str:
    if media and ("+gzip" in media or media.endswith(".gzip")):
        stream = gzip.GzipFile(fileobj=io.BytesIO(data))
    elif media and ("+zstd" in media or media.endswith(".zstd")):
        with tempfile.TemporaryFile() as decoded:
            subprocess.run(["zstd", "-q", "-d", "-c"], input=data, stdout=decoded, stderr=subprocess.PIPE, check=True)
            decoded.seek(0)
            digest = hashlib.sha256()
            for block in iter(lambda: decoded.read(1024 * 1024), b""):
                digest.update(block)
            return "sha256:" + digest.hexdigest()
    elif data.startswith(b"\x1f\x8b"):
        stream = gzip.GzipFile(fileobj=io.BytesIO(data))
    elif media in {None, "application/vnd.oci.image.layer.v1.tar", "application/vnd.docker.image.rootfs.diff.tar"} or "tar" in (media or ""):
        stream = io.BytesIO(data)
    else:
        raise ValueError(f"unsupported image layer media type: {media}")
    digest = hashlib.sha256()
    try:
        with stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except (OSError, EOFError, zlib.error) as exc:
        raise ValueError(f"image layer decompression failed: {exc}") from exc
    return "sha256:" + digest.hexdigest()


def _validate_oci(tf: tarfile.TarFile, members: dict, manifest: dict) -> dict:
    layout = json.loads(_member_bytes(tf, members, "oci-layout"))
    if not isinstance(layout, dict) or layout.get("imageLayoutVersion") != "1.0.0":
        raise ValueError("unsupported OCI image layout")
    index = json.loads(_member_bytes(tf, members, "index.json"))
    if not isinstance(index, dict) or index.get("schemaVersion") != 2 or not isinstance(index.get("manifests"), list) or not index["manifests"]:
        raise ValueError("OCI image index is missing or malformed")
    indexes = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
    image_manifests = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
    config_types = {"application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json"}
    layer_types = {"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip",
                   "application/vnd.oci.image.layer.v1.tar+zstd", "application/vnd.docker.image.rootfs.diff.tar.gzip",
                   "application/vnd.docker.image.rootfs.diff.tar"}
    used: set[str] = {"oci-layout", "index.json"}
    leaves: list[tuple[str, bytes, dict]] = []
    attestation_targets: set[str] = set()
    image_refs = {row.get("annotations", {}).get("io.containerd.image.name") for row in index["manifests"]
                  if isinstance(row, dict) and isinstance(row.get("annotations"), dict)
                  and row.get("annotations", {}).get("io.containerd.image.name")}
    if len(image_refs) != 1:
        raise ValueError("OCI archive must identify exactly one import image reference")

    def descend(descriptor: object, root_digest: str | None = None) -> None:
        media, data = _descriptor(tf, members, descriptor, allowed_media=indexes | image_manifests)
        digest = descriptor["digest"]
        used.add("blobs/sha256/" + digest.removeprefix("sha256:"))
        selected_root = root_digest or digest
        obj = json.loads(data)
        if media in indexes:
            children = obj.get("manifests") if isinstance(obj, dict) else None
            if not isinstance(children, list) or not children:
                raise ValueError("nested OCI index has no image descriptors")
            for child in children:
                platform = child.get("platform") if isinstance(child, dict) else None
                annotations = child.get("annotations", {}) if isinstance(child, dict) else {}
                is_attestation = isinstance(annotations, dict) and annotations.get("vnd.docker.reference.type") == "attestation-manifest"
                if is_attestation:
                    attestation_media, attestation_bytes = _descriptor(tf, members, child, allowed_media=image_manifests)
                    attestation = json.loads(attestation_bytes)
                    if platform != {"architecture": "unknown", "os": "unknown"} or not isinstance(attestation, dict):
                        raise ValueError("OCI auxiliary attestation descriptor is malformed")
                    att_config = attestation.get("config")
                    if isinstance(att_config, dict):
                        _att_media, _att_data = _descriptor(tf, members, att_config, allowed_media=config_types)
                        used.add("blobs/sha256/" + att_config["digest"].removeprefix("sha256:"))
                    for layer_desc in attestation.get("layers", []):
                        _att_media, _att_data = _descriptor(tf, members, layer_desc, allowed_media={"application/vnd.in-toto+json"})
                        used.add("blobs/sha256/" + layer_desc["digest"].removeprefix("sha256:"))
                        try:
                            payload = json.loads(_att_data)
                        except json.JSONDecodeError as exc:
                            raise ValueError("OCI auxiliary attestation payload is malformed") from exc
                        if not isinstance(payload, dict) or not isinstance(annotations.get("vnd.docker.reference.digest"), str):
                            raise ValueError("OCI auxiliary attestation reference is malformed")
                        attestation_targets.add(annotations["vnd.docker.reference.digest"].removeprefix("sha256:"))
                    used.add("blobs/sha256/" + child["digest"].removeprefix("sha256:"))
                    continue
                if platform is not None and (not isinstance(platform, dict) or platform.get("os") != "linux" or platform.get("architecture") != "amd64"):
                    raise ValueError("OCI image index contains a contradictory platform selection")
                descend(child, selected_root)
        else:
            platform = descriptor.get("platform")
            if platform is not None and (not isinstance(platform, dict) or platform.get("os") != "linux" or platform.get("architecture") != "amd64"):
                raise ValueError("OCI image descriptor selects a different platform")
            leaves.append((selected_root, data, obj))

    for row in index["manifests"]:
        platform = row.get("platform") if isinstance(row, dict) else None
        if platform is not None and (not isinstance(platform, dict) or platform.get("os") != "linux" or platform.get("architecture") != "amd64"):
            raise ValueError("OCI root index contains a contradictory platform selection")
        descend(row)
    if len(leaves) != 1:
        raise ValueError("OCI archive must contain exactly one selected image manifest")
    image_id, raw_manifest, image_manifest = leaves[0]
    image_manifest_digest = next((name.removeprefix("blobs/sha256/") for name in used
                                  if name.startswith("blobs/sha256/") and
                                  hashlib.sha256(_member_bytes(tf, members, name)).digest() == hashlib.sha256(raw_manifest).digest()), None)
    if attestation_targets and attestation_targets != {image_manifest_digest}:
        raise ValueError("OCI auxiliary attestations reference a different platform manifest")
    if not isinstance(image_manifest, dict) or image_manifest.get("schemaVersion") != 2:
        raise ValueError("OCI image manifest is malformed")
    config_media, config_bytes = _descriptor(tf, members, image_manifest.get("config"), allowed_media=config_types)
    config_digest = image_manifest["config"]["digest"]
    used.add("blobs/sha256/" + config_digest.removeprefix("sha256:"))
    config = json.loads(config_bytes)
    if not isinstance(config, dict) or f"{config.get('os')}/{config.get('architecture')}" != manifest.get("platform"):
        raise ValueError("OCI config platform disagrees with signed platform")
    _check_image_labels(config, manifest)
    layers = image_manifest.get("layers")
    diff_ids = config.get("rootfs", {}).get("diff_ids")
    if not isinstance(layers, list) or not isinstance(diff_ids, list) or len(layers) != len(diff_ids):
        raise ValueError("OCI layer descriptors do not match config diff IDs")
    layer_paths = []
    for descriptor, diff_id in zip(layers, diff_ids):
        media, compressed = _descriptor(tf, members, descriptor, allowed_media=layer_types)
        layer_path = "blobs/sha256/" + descriptor["digest"].removeprefix("sha256:")
        layer_paths.append(layer_path)
        used.add(layer_path)
        if not isinstance(diff_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", diff_id) or _uncompressed_layer_digest(compressed, media) != diff_id:
            raise ValueError("OCI uncompressed layer diff ID disagrees with config")
    compat_rows = json.loads(_member_bytes(tf, members, "manifest.json"))
    if not isinstance(compat_rows, list) or len(compat_rows) != 1 or not isinstance(compat_rows[0], dict):
        raise ValueError("OCI Docker-compatibility manifest must select exactly one image")
    compat = compat_rows[0]
    compat_ref = compat.get("RepoTags")
    if compat.get("Config") != "blobs/sha256/" + config_digest.removeprefix("sha256:") or compat.get("Layers") != layer_paths:
        raise ValueError("OCI Docker-compatibility manifest disagrees with selected config/layers")
    if not isinstance(compat_ref, list) or len(compat_ref) != 1 or not isinstance(compat_ref[0], str):
        raise ValueError("OCI Docker-compatibility manifest must contain exactly one import tag")
    image_ref = next(iter(image_refs))
    if image_ref not in {compat_ref[0], "docker.io/library/" + compat_ref[0]}:
        raise ValueError("OCI image reference disagrees with Docker-compatibility import tag")
    used.add("manifest.json")
    unexpected = set(members) - used
    if "repositories" in unexpected:
        try:
            repositories = json.loads(_member_bytes(tf, members, "repositories"))
        except json.JSONDecodeError as exc:
            raise ValueError("OCI Docker-compatibility repositories map is malformed") from exc
        image_name, _, image_tag = compat_ref[0].rpartition(":")
        image_name = image_name.rsplit("/", 1)[-1]
        if (not image_name or not image_tag or not diff_ids
                or repositories != {image_name: {image_tag: diff_ids[-1].removeprefix("sha256:")}}):
            raise ValueError("OCI Docker-compatibility repositories map disagrees with selected image")
        used.add("repositories")
        unexpected.remove("repositories")
    non_blob_extras = {name for name in unexpected if not name.startswith("blobs/sha256/")}
    if non_blob_extras:
        raise ValueError("OCI archive contains unreferenced image blobs")
    if unexpected:
        _validate_exporter_layer_metadata(tf, members, unexpected, diff_ids, config)
    if manifest.get("image_id") not in {image_id, config_digest}:
        raise ValueError(f"OCI image/index ID disagrees with signed identity: {manifest.get('image_id')} != {image_id} or {config_digest}")
    if manifest.get("image_config_id") not in {None, config_digest}:
        raise ValueError("OCI config ID disagrees with signed config digest")
    return {"image_id": manifest.get("image_id"), "image_index_id": image_id, "image_config_id": config_digest,
            "image_ref": compat_ref[0],
            "platform_manifest_digest": "sha256:" + hashlib.sha256(raw_manifest).hexdigest()}


def _check_image_labels(config: dict, manifest: dict) -> None:
    labels = config.get("config", {}).get("Labels") or {}
    if labels.get("org.opencontainers.image.revision") != manifest.get("source_commit") or labels.get("org.opencontainers.image.version") != manifest.get("version"):
        raise ValueError("image labels disagree with signed source/version")
    if manifest.get("version") == EXPECTED_VERSION and (labels.get("org.volt.oidc-deployment-modes") != "demo,external"
            or labels.get("org.volt.compose-install.contract") != "1"
            or labels.get("org.volt.compose.source-snapshot") != manifest.get("source_snapshot")):
        raise ValueError("image lacks the required Compose capability or source snapshot binding")


def _raw_json_object_fields(raw: bytes) -> dict[str, bytes]:
    """Return exact encoded values from one JSON object without reserializing children."""
    try:
        text = raw.decode("utf-8")
        decoder = json.JSONDecoder()
        offset = 1
        fields = {}
        while True:
            while text[offset].isspace() or text[offset] == ",":
                offset += 1
            if text[offset] == "}":
                return fields
            key, offset = decoder.raw_decode(text, offset)
            if not isinstance(key, str):
                raise ValueError("legacy exporter metadata key is malformed")
            while text[offset].isspace():
                offset += 1
            if text[offset] != ":":
                raise ValueError("legacy exporter metadata object is malformed")
            offset += 1
            while text[offset].isspace():
                offset += 1
            start = offset
            _value, offset = decoder.raw_decode(text, offset)
            fields[key] = text[start:offset].encode("utf-8")
    except (UnicodeDecodeError, json.JSONDecodeError, IndexError) as exc:
        raise ValueError("legacy exporter metadata object is malformed") from exc


def _docker_config_equivalent(legacy: object, selected: object) -> bool:
    if not isinstance(legacy, dict) or not isinstance(selected, dict):
        return False
    zero_values = {
        "Hostname": "", "Domainname": "", "User": "", "AttachStdin": False,
        "AttachStdout": False, "AttachStderr": False, "Tty": False,
        "OpenStdin": False, "StdinOnce": False, "Env": None, "Cmd": None,
        "Image": "", "Volumes": None, "WorkingDir": "", "Entrypoint": None,
        "OnBuild": None, "Labels": None,
    }
    keys = set(legacy) | set(selected)
    for key in keys:
        if key in legacy and key in selected:
            if legacy[key] != selected[key]:
                return False
        elif key not in zero_values or legacy.get(key, selected.get(key)) != zero_values[key]:
            return False
    return True


def _validate_exporter_layer_metadata(tf: tarfile.TarFile, members: dict, extras: set[str],
                                     diff_ids: list, config: dict) -> None:
    """Validate Moby docker-save v1 IDs against the selected ordered layer chain."""
    if len(extras) != len(diff_ids) or not diff_ids:
        raise ValueError("OCI archive contains unreferenced image blobs")
    records: dict[str, tuple[dict, bytes]] = {}
    for name in extras:
        digest = name.removeprefix("blobs/sha256/")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("OCI archive contains unsupported unreferenced image blobs")
        raw = _member_bytes(tf, members, name)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("OCI exporter metadata content address mismatch")
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("OCI exporter layer metadata is malformed") from exc
        layer_id = record.get("id") if isinstance(record, dict) else None
        if not isinstance(layer_id, str) or not re.fullmatch(r"[0-9a-f]{64}", layer_id):
            raise ValueError("OCI exporter layer metadata identity is malformed")
        if layer_id in records:
            raise ValueError("OCI exporter layer metadata contains duplicate identities")
        parent = record.get("parent")
        if parent is not None and (not isinstance(parent, str) or not re.fullmatch(r"[0-9a-f]{64}", parent)):
            raise ValueError("OCI exporter layer metadata parent is malformed")
        if (not isinstance(record.get("created"), str) or record.get("os") != "linux"
                or not isinstance(record.get("container_config"), dict)):
            raise ValueError("OCI exporter layer metadata has unsupported fields")
        allowed = {"id", "created", "container_config", "os"}
        if "parent" in record:
            allowed.add("parent")
        if "config" in record:
            allowed |= {"config", "architecture"}
            legacy_config = record.get("config")
            if (not isinstance(legacy_config, dict) or record.get("architecture") != config.get("architecture")
                    or record.get("os") != config.get("os")
                    or (legacy_config.get("Labels") or {}) != (config.get("config", {}).get("Labels") or {})):
                raise ValueError("OCI exporter final layer metadata disagrees with image config")
        if set(record) != allowed:
            raise ValueError("OCI exporter layer metadata has unsupported fields")
        if record["container_config"] != _docker_zero_container_config():
            raise ValueError("OCI exporter container_config is not the supported zero-value form")
        records[layer_id] = (record, raw)

    ordered = []
    previous_id = None
    for index, diff_id in enumerate(diff_ids):
        if not isinstance(diff_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", diff_id):
            raise ValueError("OCI layer diff ID is malformed")
        chain_id = diff_id if not ordered else "sha256:" + hashlib.sha256((ordered[-1][1] + " " + diff_id).encode()).hexdigest()
        matches = [(layer_id, record_raw) for layer_id, (record, record_raw) in records.items()
                   if record.get("parent") == previous_id]
        # The root record omits parent; non-root records store the previous bare v1 ID.
        if index == 0:
            matches = [(layer_id, record_raw) for layer_id, (record, record_raw) in records.items()
                       if "parent" not in record]
        if len(matches) != 1:
            raise ValueError("OCI exporter legacy layer chain does not match selected layer order")
        _stored_id, raw = matches[0]
        record = json.loads(raw)
        is_final = index == len(diff_ids) - 1
        expected_parent = None if index == 0 else ordered[-1][0]
        if record.get("parent") != expected_parent:
            raise ValueError("OCI exporter legacy parent chain disagrees with selected layer order")
        if record.get("created") != (config.get("created") if is_final else "1970-01-01T00:00:00Z"):
            raise ValueError("OCI exporter legacy created metadata disagrees with selected image")
        if record.get("os") != config.get("os"):
            raise ValueError("OCI exporter legacy OS metadata disagrees with selected image")
        if is_final:
            if (record.get("architecture") != config.get("architecture")
                    or not _docker_config_equivalent(record.get("config"), config.get("config"))):
                raise ValueError("OCI exporter final runtime config disagrees with selected image config")
        elif "config" in record or "architecture" in record:
            raise ValueError("OCI exporter intermediate layer contains final image config fields")

        fields = _raw_json_object_fields(raw)
        fields.pop("id", None)
        if not is_final:
            # Moby sets V1Image.OS after computing every intermediate v1.CreateID.
            fields.pop("os", None)
        fields["layer_id"] = json.dumps(chain_id, separators=(",", ":")).encode()
        if index:
            # Moby's v1.CreateID hashes the full digest parent; the saved record stores its bare encoding.
            fields["parent"] = json.dumps("sha256:" + expected_parent, separators=(",", ":")).encode()
        material = b"{" + b",".join(json.dumps(key).encode() + b":" + fields[key] for key in sorted(fields)) + b"}"
        expected_id = hashlib.sha256(material).hexdigest()
        if expected_id not in records or expected_id != record["id"]:
            raise ValueError("OCI exporter legacy layer ID does not derive from selected layer/config")
        ordered.append((record["id"], chain_id))
        previous_id = record["id"]
    if len(ordered) != len(records):
        raise ValueError("OCI archive contains unrelated exporter layer metadata")


def _docker_zero_container_config() -> dict:
    return {"Hostname": "", "Domainname": "", "User": "", "AttachStdin": False,
            "AttachStdout": False, "AttachStderr": False, "Tty": False, "OpenStdin": False,
            "StdinOnce": False, "Env": None, "Cmd": None, "Image": "", "Volumes": None,
            "WorkingDir": "", "Entrypoint": None, "OnBuild": None, "Labels": None}


def validate_docker_archive(image_tar: Path, manifest: dict) -> dict:
    """Validate classic Docker-save or single-platform OCI/containerd archives before import."""
    try:
        with tarfile.open(image_tar, "r:*") as tf:
            all_members = tf.getmembers()
            if len({m.name for m in all_members}) != len(all_members):
                raise ValueError("Docker image archive contains duplicate paths")
            if any(not (m.isfile() or m.isdir()) for m in all_members):
                raise ValueError("Docker image archive contains links or special files")
            members = {m.name: m for m in all_members if m.isfile()}
            if "index.json" in members:
                return _validate_oci(tf, members, manifest)
            manifest_member = members.get("manifest.json")
            if not manifest_member:
                raise ValueError("image.tar is neither Docker-save nor OCI image-layout format")
            manifest_stream = tf.extractfile(manifest_member)
            if manifest_stream is None:
                raise ValueError("Docker image manifest cannot be read")
            rows = json.load(manifest_stream)
            if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
                raise ValueError("offline image archive must contain exactly one image")
            row = rows[0]
            repo_tags = row.get("RepoTags")
            if not isinstance(repo_tags, list) or len(repo_tags) != 1 or not isinstance(repo_tags[0], str) or not repo_tags[0] or any(c.isspace() for c in repo_tags[0]):
                raise ValueError("Docker-save archive must contain exactly one import image tag")
            config_name = row.get("Config")
            config_member = members.get(config_name)
            if not isinstance(config_name, str) or not config_member:
                raise ValueError("Docker image config is missing")
            config_bytes = tf.extractfile(config_member).read()
            config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
            if manifest.get("image_id") != config_digest:
                raise ValueError("Docker-save local image ID differs from config digest")
            if config_digest != manifest.get("image_config_id", manifest.get("image_id")):
                raise ValueError("Docker archive config digest differs from signed config ID")
            config = json.loads(config_bytes)
            if not isinstance(config, dict):
                raise ValueError("Docker image config is not an object")
            os_name, arch = config.get("os"), config.get("architecture")
            if f"{os_name}/{arch}" != manifest.get("platform"):
                raise ValueError("Docker archive config platform differs from signed platform")
            _check_image_labels(config, manifest)
            layer_names = row.get("Layers")
            diff_ids = config.get("rootfs", {}).get("diff_ids")
            if not isinstance(layer_names, list) or not isinstance(diff_ids, list) or len(layer_names) != len(diff_ids):
                raise ValueError("Docker archive layer descriptors do not match config diff IDs")
            for layer_name, diff_id in zip(layer_names, diff_ids):
                layer = members.get(layer_name)
                if not layer or not isinstance(diff_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", diff_id):
                    raise ValueError("Docker archive layer missing or malformed")
                compressed = tf.extractfile(layer).read()
                digest = _uncompressed_layer_digest(compressed, None)
                if digest != diff_id:
                    raise ValueError("Docker archive layer digest differs from config diff ID")
            allowed = {"manifest.json", config_name, *layer_names}
            if "repositories" in members:
                allowed.add("repositories")
            if set(members) != allowed:
                raise ValueError("Docker-save archive contains unreferenced or unsupported files")
            return {"image_id": config_digest, "image_index_id": None, "image_config_id": config_digest,
                    "image_ref": repo_tags[0],
                    "platform_manifest_digest": None}
    except (tarfile.TarError, OSError, json.JSONDecodeError, TypeError) as exc:
        raise ValueError(f"invalid Docker image archive: {exc}") from exc


def safe_extract(archive: Path, dest: Path) -> None:
    total = 0
    seen: set[str] = set()
    with tarfile.open(archive, "r:*") as tf:
        for member in tf:
            p = PurePosixPath(member.name)
            if p.is_absolute() or ".." in p.parts or not p.parts or member.name in seen:
                raise ValueError(f"unsafe or duplicate archive path: {member.name}")
            seen.add(member.name)
            if not (member.isfile() or member.isdir()):
                raise ValueError(f"links and special files are prohibited: {member.name}")
            total += member.size
            if total > MAX_UNPACKED:
                raise ValueError("archive exceeds the 20 GiB unpacked limit")
        tf.extractall(dest, filter="data")


def verify_directory(directory: Path, cosign: str, *, public_key: Path | None = None, trusted_root: Path | None = None, trusted_root_sha256: str | None = None,
                     identity: str = EXPECTED_IDENTITY, issuer: str = EXPECTED_ISSUER,
                     expected_source: str | None = None, expected_image: str | None = None) -> dict:
    if identity != EXPECTED_IDENTITY or issuer != EXPECTED_ISSUER:
        raise ValueError("unexpected release signer identity or OIDC issuer")
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if not isinstance(manifest, dict):
        raise ValueError("release manifest is not an object")
    if manifest.get("schema") != "volt-offline-release/v1" or manifest.get("version") not in SUPPORTED_ARCHIVE_VERSIONS:
        raise ValueError("unsupported release manifest or version")
    if manifest.get("platform") != EXPECTED_PLATFORM:
        raise ValueError("release platform metadata mismatch")
    registry_digest = manifest.get("registry_digest", "")
    if not isinstance(registry_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", registry_digest):
        raise ValueError("published OCI registry digest metadata missing or malformed")
    if manifest.get("signer_identity") != identity or manifest.get("oidc_issuer") != issuer:
        raise ValueError("release signer identity metadata mismatch")
    if expected_source and manifest.get("source_commit") != expected_source:
        raise ValueError("source revision does not match requested revision")
    if expected_image and manifest.get("image_id") != expected_image:
        raise ValueError("image ID does not match requested image")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("signed file inventory missing")
    if (directory / "trusted_root.json").exists():
        raise ValueError("archive-supplied Sigstore trusted roots are forbidden")
    required = {"image.tar", "source.tar", "source.bundle", "sbom.syft.json", "sbom.spdx.json",
                "release-scan.json", "provenance.json", "registry-digest.txt", "notice-manifest.json", "VERIFY.txt"}
    if manifest["version"] == EXPECTED_VERSION:
        required.update({"volt-compose.tar.gz", "volt-compose.tar.gz.sha256"})
    else:
        required.update({"tools-g7-local-preview.py", "launcher-guide.txt"})
    if not required <= set(files):
        raise ValueError(f"required signed payload members missing: {sorted(required - set(files))}")
    actual_payload = {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()
                      and p.relative_to(directory).as_posix() not in {"manifest.json", "SHA256SUMS", "signature.bundle"}}
    if actual_payload != set(files):
        raise ValueError("actual payload files do not exactly match the signed inventory")
    # Authenticate the manifest before interpreting any archive payload or asking Git
    # to inspect its embedded repository. The signed inventory then authenticates all
    # payload bytes before any checkout can trigger filters or smudge handlers.
    signature = directory / "signature.bundle"
    if not signature.is_file():
        raise ValueError("Cosign signature bundle missing")
    if public_key:
        test_bundle = json.loads(signature.read_text())
        if test_bundle.get("schema") != "volt-test-signature/v1":
            raise ValueError("test-key verification only accepts the explicit local fixture format")
        if test_bundle.get("public_key_sha256") != sha(public_key):
            raise ValueError("test signature public key identity mismatch")
        signature_bytes = base64.b64decode(test_bundle.get("signature_b64", ""), validate=True)
        with tempfile.TemporaryDirectory(prefix="volt-test-signature-") as temp:
            sig_path = Path(temp) / "signature.bin"
            sig_path.write_bytes(signature_bytes)
            subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
                            "-rawin", "-in", str(manifest_path), "-sigfile", str(sig_path)],
                           check=True, capture_output=True, text=True)
    else:
        command = [cosign, "verify-blob", "--bundle", str(signature)]
        if trusted_root is not None:
            if not trusted_root.is_file() or not trusted_root_sha256 or sha(trusted_root) != trusted_root_sha256:
                raise ValueError("independently provisioned Sigstore trusted root is missing or fails its out-of-band SHA-256 pin")
            command += ["--trusted-root", str(trusted_root)]
        command += ["--certificate-identity", identity, "--certificate-oidc-issuer", issuer, str(manifest_path)]
        run(command)
    for name, expected in files.items():
        if not isinstance(name, str) or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("signed file inventory entry is malformed")
        rel = PurePosixPath(name)
        path = (directory / Path(*rel.parts)).resolve()
        if rel.is_absolute() or ".." in rel.parts or directory.resolve() not in path.parents:
            raise ValueError(f"unsafe signed file path: {name}")
        if not path.is_file() or sha(path) != expected:
            raise ValueError(f"payload missing or digest mismatch: {name}")
    if manifest.get("version") == EXPECTED_VERSION and manifest.get("source_snapshot") != "sha256:" + sha(directory / "source.tar"):
        raise ValueError("signed source snapshot digest does not match source.tar")
    checksums = directory / "SHA256SUMS"
    if not checksums.is_file():
        raise ValueError("SHA256SUMS missing")
    sum_names = set()
    for line in checksums.read_text().splitlines():
        digest, sep, name = line.partition("  ")
        if not sep or len(digest) != 64:
            raise ValueError("malformed SHA256SUMS entry")
        if name in sum_names:
            raise ValueError(f"duplicate checksum entry: {name}")
        sum_names.add(name)
        path = (directory / name).resolve()
        if directory.resolve() not in path.parents or not path.is_file() or sha(path) != digest:
            raise ValueError(f"checksum failed: {name}")
    actual_names = {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file() and p.relative_to(directory).as_posix() != "SHA256SUMS"}
    if sum_names != actual_names:
        raise ValueError("SHA256SUMS does not cover the complete archive payload")
    if manifest.get("registry_digest") != (directory / "registry-digest.txt").read_text().strip():
        raise ValueError("registry digest file disagrees with signed manifest")
    notice = json.loads((directory / "notice-manifest.json").read_text())
    if not isinstance(notice, dict):
        raise ValueError("notice inventory is not an object")
    if notice.get("image_id") != manifest.get("image_id") or notice.get("platform") != manifest.get("platform"):
        raise ValueError("notice inventory image/platform disagrees with signed release manifest")
    provenance_validator.validate(json.loads((directory / "provenance.json").read_text()), manifest.get("source_commit"))
    bundle_heads = subprocess.check_output(["git", "bundle", "list-heads", str(directory / "source.bundle")], text=True)
    if not any(line.split()[0] == manifest.get("source_commit") for line in bundle_heads.splitlines() if line.split()):
        raise ValueError("Git source bundle does not contain the signed source commit")
    with tempfile.TemporaryDirectory(prefix="volt-source-bundle-") as temp:
        checkout = Path(temp) / "source"
        subprocess.run(["git", "clone", "--quiet", "--no-checkout", str(directory / "source.bundle"), str(checkout)], check=True, capture_output=True, text=True)
        subprocess.run(["git", "-C", str(checkout), "checkout", "--quiet", "--detach", manifest["source_commit"]], check=True, capture_output=True, text=True)
        source_tar = subprocess.check_output(["git", "-C", str(checkout), "archive", "--format=tar", manifest["source_commit"]])
        if source_tar != (directory / "source.tar").read_bytes():
            raise ValueError("source.tar does not match the exact Git bundle commit")
        if manifest["version"] == EXPECTED_VERSION:
            verify_compose_bundle(directory / "volt-compose.tar.gz", manifest["version"], registry_digest, checkout)
        else:
            helper = checkout / "tools" / "g7_local_preview.py"
            if not helper.is_file() or helper.read_bytes() != (directory / "tools-g7-local-preview.py").read_bytes():
                raise ValueError("packaged host launcher does not match the exact source bundle")
    scan_report = json.loads((directory / "release-scan.json").read_text())
    scan_metadata = scan_report.get("Metadata") if isinstance(scan_report, dict) else None
    if not isinstance(scan_report, dict) or scan_report.get("SchemaVersion") != 2 or scan_report.get("ArtifactType") != "container_image" or not isinstance(scan_metadata, dict) or scan_metadata.get("ImageID") != manifest.get("image_id") or not isinstance(scan_report.get("Results"), list) or not scan_report["Results"]:
        raise ValueError("full Trivy report is incomplete or bound to a different image")
    identity = validate_docker_archive(directory / "image.tar", manifest)
    if identity.get("image_config_id") != manifest.get("image_config_id") or identity.get("image_index_id") != manifest.get("image_index_id") or identity.get("platform_manifest_digest") != manifest.get("platform_manifest_digest"):
        raise ValueError("image config/index identity disagrees with signed archive metadata")
    if public_key:
        return manifest
    return manifest


def create_archive(directory: Path, archive_path: Path) -> None:
    free = shutil.disk_usage(archive_path.parent).free
    source_bytes = sum(p.stat().st_size for p in directory.rglob("*") if p.is_file())
    if free < source_bytes + max(512 * 1024**2, source_bytes // 20):
        raise ValueError("insufficient free space to create a duplicate offline archive")
    with tarfile.open(archive_path, "w") as tf:
        for path in sorted(directory.rglob("*")):
            tf.add(path, arcname=path.relative_to(directory).as_posix(), recursive=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--directory", required=True, type=Path)
    prepare.add_argument("--version", required=True)
    prepare.add_argument("--source-sha", required=True)
    prepare.add_argument("--image-id", required=True)
    prepare.add_argument("--registry-digest", required=True)
    prepare.add_argument("--platform", required=True)
    prepare.add_argument("--identity", default=EXPECTED_IDENTITY)
    prepare.add_argument("--issuer", default=EXPECTED_ISSUER)
    sign = commands.add_parser("sign")
    sign.add_argument("--directory", required=True, type=Path)
    sign.add_argument("--cosign", default="cosign")
    sign.add_argument("--key", help="test-only local key; production signing uses GitHub OIDC in the guarded workflow")
    sign.add_argument("--production-oidc", action="store_true")
    sign.add_argument("--approval", help="required exact release approval reference for production OIDC signing")
    pack = commands.add_parser("pack")
    pack.add_argument("--directory", required=True, type=Path)
    pack.add_argument("--archive", required=True, type=Path)
    pack.add_argument("--test-public-key", type=Path, help="test-only local fixture key; never use for releases")
    verify = commands.add_parser("verify")
    verify.add_argument("--archive", required=True, type=Path)
    verify.add_argument("--cosign", default="cosign")
    verify.add_argument("--test-public-key", type=Path, help="test-only local fixture key")
    verify.add_argument("--trusted-root", type=Path, help="optional independently provisioned Sigstore trusted root; never read from archive")
    verify.add_argument("--trusted-root-sha256", help="out-of-band SHA-256 for --trusted-root")
    verify.add_argument("--identity", default=EXPECTED_IDENTITY)
    verify.add_argument("--issuer", default=EXPECTED_ISSUER)
    verify.add_argument("--source-sha")
    verify.add_argument("--image-id")
    load = commands.add_parser("load")
    load.add_argument("--archive", required=True, type=Path)
    load.add_argument("--cosign", default="cosign")
    load.add_argument("--test-public-key", type=Path)
    load.add_argument("--trusted-root", type=Path, help="optional independently provisioned Sigstore trusted root; never read from archive")
    load.add_argument("--trusted-root-sha256", help="out-of-band SHA-256 for --trusted-root")
    load.add_argument("--identity", default=EXPECTED_IDENTITY)
    load.add_argument("--issuer", default=EXPECTED_ISSUER)
    load.add_argument("--docker", default="docker")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            manifest = build_manifest(args.directory, args.version, args.source_sha, args.image_id,
                                      args.platform, args.identity, args.issuer, args.registry_digest)
            (args.directory / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
            print(f"prepared unsigned source/image manifest {args.source_sha} {args.image_id}")
        elif args.command == "sign":
            if args.production_oidc and not args.approval:
                raise ValueError("production OIDC signing requires the protected environment approval reference")
            if args.key:
                if args.production_oidc:
                    raise ValueError("test key and production OIDC modes are mutually exclusive")
                signature = args.directory / "signature.bin"
                subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", args.key, "-rawin",
                                "-in", str(args.directory / "manifest.json"), "-out", str(signature)], check=True)
                public = subprocess.check_output(["openssl", "pkey", "-in", args.key, "-pubout"], text=True)
                public_bytes = subprocess.check_output(["openssl", "pkey", "-in", args.key, "-pubout"])
                bundle = {"schema": "volt-test-signature/v1", "public_key_sha256": hashlib.sha256(public_bytes).hexdigest(),
                          "signature_b64": base64.b64encode(signature.read_bytes()).decode("ascii")}
                (args.directory / "signature.bundle").write_text(json.dumps(bundle, sort_keys=True) + "\n")
                signature.unlink()
            elif not args.production_oidc:
                raise ValueError("signing requires an explicit test key or approved production OIDC mode")
            else:
                run([args.cosign, "sign-blob", "--yes", "--bundle", str(args.directory / "signature.bundle"),
                     str(args.directory / "manifest.json")])
            checksum_rows = []
            for path in sorted(p for p in args.directory.rglob("*") if p.is_file() and p.relative_to(args.directory).as_posix() != "SHA256SUMS"):
                checksum_rows.append(f"{sha(path)}  {path.relative_to(args.directory).as_posix()}")
            (args.directory / "SHA256SUMS").write_text("\n".join(checksum_rows) + "\n")
        elif args.command == "pack":
            safe = args.directory.resolve()
            verify_directory(safe, "cosign", public_key=args.test_public_key)
            create_archive(safe, args.archive)
        elif args.command == "verify":
            with tempfile.TemporaryDirectory(prefix="volt-release-verify-") as temp:
                root = Path(temp)
                safe_extract(args.archive, root)
                manifest = verify_directory(root, args.cosign, public_key=args.test_public_key, trusted_root=args.trusted_root, trusted_root_sha256=args.trusted_root_sha256,
                                            identity=args.identity, issuer=args.issuer,
                                            expected_source=args.source_sha, expected_image=args.image_id)
                print(f"verified {manifest['version']} source {manifest['source_commit']} image {manifest['image_id']}")
        elif args.command == "load":
            with tempfile.TemporaryDirectory(prefix="volt-release-load-") as temp:
                root = Path(temp)
                safe_extract(args.archive, root)
                manifest = verify_directory(root, args.cosign, public_key=args.test_public_key, trusted_root=args.trusted_root, trusted_root_sha256=args.trusted_root_sha256,
                                            identity=args.identity, issuer=args.issuer)
                image_tar = root / "image.tar"
                subprocess.run([args.docker, "image", "load", "--input", str(image_tar)], check=True, text=True, capture_output=True)
                admitted = validate_docker_archive(image_tar, manifest)
                info = json.loads(subprocess.check_output([args.docker, "image", "inspect", admitted["image_ref"]], text=True))[0]
                labels = info.get("Config", {}).get("Labels") or {}
                accepted_ids = {manifest["image_id"], manifest["image_config_id"]}
                if admitted["image_index_id"]:
                    accepted_ids.add(admitted["image_index_id"])
                if info.get("Id") not in accepted_ids or info.get("Os") + "/" + info.get("Architecture") != manifest["platform"]:
                    raise ValueError("loaded Docker image identity or platform differs from signed manifest")
                if labels.get("org.opencontainers.image.revision") != manifest["source_commit"] or labels.get("org.opencontainers.image.version") != manifest["version"]:
                    raise ValueError("loaded Docker image labels differ from signed source/version metadata")
                print("signature, archive, image ID, platform, source revision and version verified; image loaded")
        return 0
    except (OSError, ValueError, TypeError, AttributeError, UnicodeError, KeyError, subprocess.CalledProcessError, tarfile.TarError, json.JSONDecodeError) as exc:
        print(f"release archive rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
