"""Verify the closed local installer bundle and its authenticated runtime graph."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

RC2_FILES = ("VERSION", "README.md", "backup-restore.md", "compose.yaml", "demo.yaml",
    "compose.env.example", "oidc.example.json", "setup.py")
RC3_FILES = (*RC2_FILES, "okta-publisher.yaml", "okta-publisher.example.json")
RC4_FILES = (*RC3_FILES, "local.yaml", "local-restore.yaml", "launcher.sh", "offline-host.sh", "release-image.ref")
PROVENANCE_TYPE = "https://volt.dev/attestation/easy-install/v1"
SOURCE_REPOSITORY = "https://github.com/njvenis/volt"


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def verify_bundle(path: Path, *, reference: str) -> dict:
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        names = [item.name for item in members]
        if len(names) != len(set(names)) or any(not item.isfile() for item in members):
            raise ValueError("installer archive must contain unique regular files only")
        roots = set()
        files = {}
        for member in members:
            parts = PurePosixPath(member.name).parts
            if (len(parts) != 2 or any(part in ("", ".", "..") for part in parts)
                    or PurePosixPath(member.name).is_absolute()):
                raise ValueError("installer archive member path is unsafe")
            roots.add(parts[0])
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("installer archive member content is missing")
            files[parts[1]] = stream.read()
    if len(roots) != 1 or files.get("VERSION", b"").decode().strip() != "0.1.0-rc.4":
        raise ValueError("installer archive does not contain the pinned RC4 contract")
    manifest = json.loads(files.get("manifest.json", b"{}"))
    expected = {name: sha256(files[name]) for name in RC4_FILES if name in files}
    if (not isinstance(manifest, dict) or set(files) != {*RC4_FILES, "manifest.json"}
            or set(manifest) != {"format_version", "bundle_version", "release_image", "files"}
            or manifest["format_version"] != 1 or manifest["bundle_version"] != "0.1.0-rc.4"
            or manifest["release_image"] != reference or files["release-image.ref"].decode().strip() != reference
            or manifest["files"] != expected or reference.encode() not in files["README.md"]):
        raise ValueError("installer archive inventory or runtime reference does not match its signed manifest")
    return {"bundle_version": manifest["bundle_version"], "release_image": reference,
            "bundle_sha256": sha256(path.read_bytes()), "launcher_sha256": sha256(files["launcher.sh"])}


def platform_children(index_data: bytes, reference: str) -> dict[str, str]:
    digest = reference.rsplit("@sha256:", 1)[-1]
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or sha256(index_data) != digest:
        raise ValueError("runtime index bytes do not match the signed immutable reference")
    index = json.loads(index_data)
    if (not isinstance(index, dict) or index.get("schemaVersion") != 2
            or not isinstance(index.get("manifests"), list)):
        raise ValueError("runtime reference is not a supported OCI image index")
    found = {}
    for descriptor in index["manifests"]:
        platform = descriptor.get("platform") or {}
        os_name, architecture = platform.get("os"), platform.get("architecture")
        if os_name == "unknown" and architecture == "unknown":
            continue
        name = f"{os_name}/{architecture}"
        if name not in {"linux/amd64", "linux/arm64"} or name in found:
            raise ValueError("runtime index must have exactly one supported Linux amd64 and arm64 child")
        child = (descriptor.get("digest") or "").removeprefix("sha256:")
        if not re.fullmatch(r"[0-9a-f]{64}", child):
            raise ValueError("runtime platform descriptor digest is malformed")
        found[name] = f"sha256:{child}"
    if set(found) != {"linux/amd64", "linux/arm64"}:
        raise ValueError("runtime index is missing a supported platform child")
    return found


def decode_statement(output: str) -> dict:
    try:
        rows = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ValueError("verified runtime provenance output is not JSON") from exc
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list) or not rows:
        raise ValueError("verified runtime provenance output has no attestations")
    statements = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("payload"), str):
            continue
        try:
            payload = base64.b64decode(row["payload"], validate=True)
            statement = json.loads(payload)
        except (ValueError, json.JSONDecodeError):
            continue
        if isinstance(statement, dict) and statement.get("predicateType") == PROVENANCE_TYPE:
            statements.append(statement)
    if len(statements) != 1:
        raise ValueError("runtime requires exactly one supported signed provenance statement")
    return statements[0]


def verify_runtime(*, image_output: str, index_data: bytes, provenance_output: str,
                   reference: str, source_revision: str, source_snapshot: str,
                   version: str, platform: str, bundle_sha256: str) -> dict:
    try:
        rows = json.loads(image_output)
    except json.JSONDecodeError as exc:
        raise ValueError("Docker runtime inspection is not valid JSON") from exc
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise ValueError("Docker runtime inspection must identify exactly one image")
    image = rows[0]
    labels = (image.get("Config") or {}).get("Labels") or {}
    actual_platform = f"{image.get('Os')}/{image.get('Architecture')}"
    if actual_platform != platform or platform not in {"linux/amd64", "linux/arm64"}:
        raise ValueError("selected runtime platform differs from the admitted engine platform")
    if image.get("Id", "").startswith("sha256:") is False:
        raise ValueError("selected runtime image has no immutable configuration ID")
    if (labels.get("org.volt.compose.source-snapshot") != source_snapshot
            or labels.get("org.opencontainers.image.revision") != source_revision
            or labels.get("org.opencontainers.image.version") != version
            or labels.get("org.volt.compose-install.contract") != "1"
            or "local" not in (labels.get("org.volt.oidc-deployment-modes") or "").split(",")):
        raise ValueError("runtime labels do not match the signed source and local-install contract")
    children = platform_children(index_data, reference)
    statement = decode_statement(provenance_output)
    digest = reference.rsplit("@sha256:", 1)[1]
    subjects = statement.get("subject")
    predicate = statement.get("predicate")
    expected_predicate = {"schema_version", "release_version", "source_repository", "source_revision",
        "source_snapshot", "image_index_digest", "platform_children", "installer_bundle_sha256"}
    if (not isinstance(subjects, list) or len(subjects) != 1
            or subjects[0].get("digest") != {"sha256": digest}
            or not isinstance(predicate, dict) or set(predicate) != expected_predicate
            or predicate.get("schema_version") != 1 or predicate.get("release_version") != version
            or predicate.get("source_repository") != SOURCE_REPOSITORY
            or predicate.get("source_revision") != source_revision
            or predicate.get("source_snapshot") != source_snapshot
            or predicate.get("image_index_digest") != f"sha256:{digest}"
            or predicate.get("installer_bundle_sha256") != bundle_sha256
            or predicate.get("platform_children") != children):
        raise ValueError("signed runtime provenance does not bind source, version, index and exact platform children")
    return {"image_id": image["Id"], "platform": platform, "source_revision": source_revision,
            "source_snapshot": source_snapshot, "image_index_digest": f"sha256:{digest}",
            "platform_children": children}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--image-output", type=Path, required=True)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--source-snapshot", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--platform", required=True)
    args = parser.parse_args()
    try:
        bundle = verify_bundle(args.bundle, reference=args.reference)
        runtime = verify_runtime(image_output=args.image_output.read_text(),
            index_data=args.index.read_bytes(), provenance_output=args.provenance.read_text(),
            reference=args.reference, source_revision=args.source_revision,
            source_snapshot=args.source_snapshot, version=args.version, platform=args.platform,
            bundle_sha256=bundle["bundle_sha256"])
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({"bundle": bundle, "runtime": runtime}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
