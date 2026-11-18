"""Independently trusted, pre-runtime verifier for the source-free installer."""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

from uvm.installer.admission import RC4_FILES, sha256, verify_runtime

MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_MEMBERS = 32
FIXTURE_POLICY = Path("/usr/local/share/volt-verifier/fixture-trust.json")


def verify_closed_bundle(path: Path, *, reference: str) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("installer bundle is missing, unsafe, or exceeds the archive size limit")
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if not members or len(members) > MAX_MEMBERS:
            raise ValueError("installer archive member count is outside the closed inventory bound")
        names = [member.name for member in members]
        if len(names) != len(set(names)):
            raise ValueError("installer archive contains duplicate members")
        roots: set[str] = set()
        files: dict[str, bytes] = {}
        for member in members:
            parts = PurePosixPath(member.name).parts
            if (not member.isfile() or member.issym() or member.islnk() or len(parts) != 2
                    or PurePosixPath(member.name).is_absolute()
                    or any(part in ("", ".", "..") for part in parts)
                    or member.size < 0 or member.size > MAX_MEMBER_BYTES):
                raise ValueError("installer archive contains unsafe path, type, or member size")
            roots.add(parts[0])
            if parts[1] in files:
                raise ValueError("installer archive contains duplicate inventory names")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("installer archive member content is missing")
            content = stream.read(MAX_MEMBER_BYTES + 1)
            if len(content) != member.size or len(content) > MAX_MEMBER_BYTES:
                raise ValueError("installer archive member content exceeds its declared bound")
            files[parts[1]] = content
    if len(roots) != 1 or set(files) != {*RC4_FILES, "manifest.json"}:
        raise ValueError("installer archive inventory is not the closed RC4 inventory")
    try:
        manifest = json.loads(files["manifest.json"])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("installer bundle manifest is invalid JSON") from exc
    expected = {name: sha256(files[name]) for name in RC4_FILES}
    manifest_keys = {"format_version", "bundle_version", "release_image", "files"}
    if FIXTURE_POLICY.is_file():
        manifest_keys.add("verifier_reference")
        verifier_reference = manifest.get("verifier_reference") if isinstance(manifest, dict) else None
        if (not isinstance(verifier_reference, str) or not re.fullmatch(
                r"127\.0\.0\.1:46150/volt-installer-verifier@sha256:[0-9a-f]{64}", verifier_reference)
                or verifier_reference.encode("ascii") not in files["launcher.sh"]):
            raise ValueError("local fixture bundle does not bind its independently pinned verifier image")
    if (not isinstance(manifest, dict) or set(manifest) != manifest_keys
            or manifest.get("format_version") != 1 or manifest.get("bundle_version") != "0.1.0-rc.4"
            or manifest.get("release_image") != reference or files["VERSION"].decode("ascii").strip() != "0.1.0-rc.4"
            or files["release-image.ref"].decode("ascii").strip() != reference
            or manifest.get("files") != expected or reference.encode("ascii") not in files["README.md"]):
        raise ValueError("installer bundle manifest, version, source inventory, or runtime reference mismatch")
    return {"bundle_sha256": sha256(path.read_bytes()), "bundle_version": "0.1.0-rc.4",
            "reference": reference, "files": len(RC4_FILES)}


def cosign(*args: str) -> str:
    if FIXTURE_POLICY.is_file():
        policy = json.loads(FIXTURE_POLICY.read_text())
        return _cosign_fixture(policy, *args)
    result = subprocess.run(("/usr/local/bin/cosign", *args), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp"})
    if result.returncode:
        raise ValueError("pinned Cosign verification failed: " + result.stderr[-1200:].strip())
    return result.stdout


def _cosign_fixture(policy: dict, *args: str) -> str:
    """Use only trust material baked into the immutable verifier fixture image."""
    public_key = Path("/usr/local/share/volt-verifier/fixture.pub")
    trusted_root = Path("/usr/local/share/volt-verifier/trusted-root.json")
    if not public_key.is_file() or not trusted_root.is_file():
        raise ValueError("fixture verifier trust material is incomplete")
    # Fixture inputs cannot choose keys, URLs or flags. Each operation still
    # requires the local Rekor bundle and inclusion proof.
    if len(args) >= 1 and args[0] == "verify-blob":
        artifact = args[-1]
        bundle_index = args.index("--bundle") + 1
        command = ("verify-blob", "--bundle", args[bundle_index], "--key", str(public_key),
                   "--trusted-root", str(trusted_root), artifact)
    elif len(args) >= 1 and args[0] == "verify":
        command = ("verify", "--key", str(public_key), "--trusted-root", str(trusted_root), args[-1])
    elif len(args) >= 1 and args[0] == "verify-attestation":
        output_index = args.index("--output-file") + 1
        output = args[output_index]
        predicate_index = args.index("--type") + 1
        predicate = args[predicate_index]
        command = ("verify-attestation", "--type", predicate, "--key", str(public_key),
                   "--trusted-root", str(trusted_root), "--output-file", output, args[-1])
    else:
        raise ValueError("fixture Cosign operation is not in the closed verification allowlist")
    result = subprocess.run(("/usr/local/bin/cosign", *command), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp",
             "REKOR_SERVER": policy["rekor_base_url"]})
    if result.returncode:
        raise ValueError("local fixture transparency verification failed: " + result.stderr[-1200:].strip())
    return result.stdout


def discover_signed_reference(bundle: Path, signature: Path, signer: str, issuer: str) -> tuple[str, str]:
    if bundle.is_symlink() or signature.is_symlink() or not bundle.is_file() or not signature.is_file():
        raise ValueError("signed bundle inputs are missing or unsafe")
    if bundle.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("installer archive exceeds the archive size limit")
    cosign("verify-blob", "--bundle", str(signature), "--certificate-identity", signer,
           "--certificate-oidc-issuer", issuer, str(bundle))
    with tarfile.open(bundle, "r:gz") as archive:
        manifests = [m for m in archive.getmembers() if PurePosixPath(m.name).name == "manifest.json"]
        if len(manifests) != 1 or not manifests[0].isfile() or manifests[0].size > MAX_MEMBER_BYTES:
            raise ValueError("signed installer must contain one bounded manifest")
        raw = archive.extractfile(manifests[0]).read(MAX_MEMBER_BYTES + 1)
    manifest = json.loads(raw)
    reference = manifest.get("release_image") if isinstance(manifest, dict) else None
    allowed_reference = (r"127\.0\.0\.1:46150/volt@sha256:[0-9a-f]{64}"
                         if FIXTURE_POLICY.is_file()
                         else r"ghcr\.io/njvenis/volt@sha256:[0-9a-f]{64}")
    if not isinstance(reference, str) or not re.fullmatch(allowed_reference, reference):
        raise ValueError("signed bundle runtime reference is malformed")
    verified = verify_closed_bundle(bundle, reference=reference)
    return reference, verified["bundle_sha256"]


def verify(args: argparse.Namespace) -> dict:
    for p in (args.bundle, args.bundle_signature, args.image_inspect, args.index):
        if p.is_symlink() or not p.is_file():
            raise ValueError("verification input is missing or is not a regular file")
    bundle = verify_closed_bundle(args.bundle, reference=args.reference)
    cosign("verify-blob", "--bundle", str(args.bundle_signature),
           "--certificate-identity", args.signer, "--certificate-oidc-issuer", args.issuer,
           str(args.bundle))
    cosign("verify", "--certificate-identity", args.signer, "--certificate-oidc-issuer", args.issuer,
           args.reference)
    provenance = args.output_dir / "verified-runtime-provenance.json"
    cosign("verify-attestation", "--type", "https://volt.dev/attestation/easy-install/v1",
           "--certificate-identity", args.signer, "--certificate-oidc-issuer", args.issuer,
           "--output-file", str(provenance), args.reference)
    runtime = verify_runtime(image_output=args.image_inspect.read_text(),
        index_data=args.index.read_bytes(), provenance_output=provenance.read_text(),
        reference=args.reference, source_revision=args.source_revision,
        source_snapshot=args.source_snapshot, version=args.version,
        platform=args.platform, bundle_sha256=bundle["bundle_sha256"])
    return {"bundle": bundle, "runtime": runtime}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--bundle-signature", type=Path, required=True)
    parser.add_argument("--bundle-only", action="store_true")
    for name in ("image-inspect", "index", "output-dir"):
        parser.add_argument("--" + name, type=Path)
    for name in ("signer", "issuer"):
        parser.add_argument("--" + name, required=True)
    for name in ("reference", "source-revision", "source-snapshot", "version", "platform"):
        parser.add_argument("--" + name)
    args = parser.parse_args()
    try:
        if args.bundle_only:
            reference, digest = discover_signed_reference(args.bundle, args.bundle_signature,
                                                           args.signer, args.issuer)
            print(f"reference={reference}\nbundle_sha256={digest}")
            return 0
        if any(getattr(args, key) is None for key in
               ("reference", "source_revision", "source_snapshot", "version", "platform")):
            parser.error("full graph verification requires reference, source, version, and platform metadata")
        if any(getattr(args, key.replace("-", "_")) is None for key in
               ("image-inspect", "index", "output-dir")):
            parser.error("full graph verification requires image inspection, index, and output paths")
        args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        result = verify(args)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, tarfile.TarError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
