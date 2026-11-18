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


def verify_platform_configs(runtime: dict, *, reference: str, source_revision: str,
                            source_snapshot: str, version: str, index_data: bytes, fixture: bool, image_output: str | None = None,
                            fetch=None) -> dict[str, str]:
    """Bind both signed platform children to actual immutable manifest/config bytes."""
    from urllib.error import HTTPError
    from urllib.parse import urlencode, urlsplit
    from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler

    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            target = urlsplit(newurl)
            if (fixture or '/blobs/' not in req.full_url or target.scheme != 'https'
                    or target.username or target.password or target.port not in (None, 443)
                    or not target.hostname or not target.hostname.endswith('.githubusercontent.com')):
                raise ValueError('registry redirect refused during child admission')
            # Blob bytes are content-addressed. Never forward the GHCR token.
            return Request(newurl, headers={'Accept': 'application/octet-stream'})

    if fixture:
        if not re.fullmatch(r'127\.0\.0\.1:46150/volt@sha256:[0-9a-f]{64}', reference):
            raise ValueError('fixture child registry is not the owned loopback registry')
        origin, repository = 'http://127.0.0.1:46150', 'volt'
    else:
        if not re.fullmatch(r'ghcr\.io/njvenis/volt@sha256:[0-9a-f]{64}', reference):
            raise ValueError('child registry is not the fixed official repository')
        origin, repository = 'https://ghcr.io', 'njvenis/volt'
    opener = build_opener(ProxyHandler({}), NoRedirect())
    token = None

    def read_json_path(path, *, limit=1024 * 1024):
        nonlocal token
        headers = {'Accept': 'application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json,application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        try:
            response = opener.open(Request(origin + path, headers=headers), timeout=20)
        except HTTPError as error:
            if fixture or error.code != 401 or token is not None:
                raise ValueError('registry child request failed closed') from None
            token_path = '/token?' + urlencode({'scope': 'repository:njvenis/volt:pull'})
            with opener.open(Request(origin + token_path), timeout=20) as response:
                document = json.loads(response.read(65537))
            token = document.get('token') or document.get('access_token')
            if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9._~+/-]+=*', token):
                raise ValueError('registry pull token invalid')
            headers['Authorization'] = 'Bearer ' + token
            response = opener.open(Request(origin + path, headers=headers), timeout=20)
        with response:
            content = response.read(limit + 1)
        if len(content) > limit:
            raise ValueError('registry child document too large')
        return content

    def fetch_document(kind, digest, size):
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            raise ValueError('registry child digest invalid')
        if type(size) is not int or not 0 < size <= 1024 * 1024:
            raise ValueError('registry child size invalid')
        raw = (fetch(kind, digest) if fetch is not None else
               read_json_path(f'/v2/{repository}/{kind}/{digest}'))
        if len(raw) != size or 'sha256:' + sha256(raw) != digest:
            raise ValueError('actual child/config bytes differ from signed digest')
        document = json.loads(raw)
        if not isinstance(document, dict):
            raise ValueError('registry child document invalid')
        return document

    descriptors = {item.get('digest'): item for item in json.loads(index_data)['manifests']}
    configs = {}
    for platform, digest in runtime['platform_children'].items():
        descriptor = descriptors[digest]
        manifest = fetch_document('manifests', digest, descriptor.get('size'))
        if descriptor.get('mediaType') != manifest.get('mediaType'):
            raise ValueError('signed child media type differs')
        config_digest = (manifest.get('config') or {}).get('digest')
        if (manifest.get('schemaVersion') != 2 or manifest.get('mediaType') not in {
                'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'}
                or not isinstance(manifest.get('layers'), list) or not manifest['layers']):
            raise ValueError('actual platform child is not an executable image manifest')
        config = fetch_document('blobs', config_digest, manifest['config'].get('size'))
        labels = (config.get('config') or {}).get('Labels') or {}
        if (f"{config.get('os')}/{config.get('architecture')}" != platform
                or labels.get('org.opencontainers.image.revision') != source_revision
                or labels.get('org.volt.compose.source-snapshot') != source_snapshot
                or labels.get('org.opencontainers.image.version') != version
                or labels.get('org.volt.compose-install.contract') != '1'
                or 'local' not in (labels.get('org.volt.oidc-deployment-modes') or '').split(',')):
            raise ValueError('actual platform config differs from signed source/platform contract')
        if manifest['config'].get('mediaType') not in {
                'application/vnd.oci.image.config.v1+json', 'application/vnd.docker.container.image.v1+json'}:
            raise ValueError('actual platform config media type unsupported')
        configs[platform] = config_digest
    selected_config = configs[runtime['platform']]
    if selected_config != runtime['image_id']:
        # Docker29's containerd image store reports the manifest/index descriptor
        # as .Id. Admit only that exact authenticated descriptor, while retaining
        # the selected config identity separately. Unknown IDs still fail closed.
        image = json.loads(image_output)[0] if image_output is not None else {}
        descriptor = image.get('Descriptor') or {}
        selected_child = runtime['platform_children'][runtime['platform']]
        expected = descriptors[selected_child] if runtime['image_id'] == selected_child else None
        if (expected is None or descriptor.get('digest') != runtime['image_id']
                or any(descriptor.get(key) != expected.get(key) for key in ('digest', 'mediaType', 'size'))
                or expected.get('mediaType') not in {'application/vnd.oci.image.manifest.v1+json',
                    'application/vnd.docker.distribution.manifest.v2+json', 'application/vnd.oci.image.index.v1+json',
                    'application/vnd.docker.distribution.manifest.list.v2+json'}):
            raise ValueError('selected Docker config/descriptor ID differs from signed platform child')
    runtime['image_config_id'] = selected_config
    runtime['image_id_kind'] = 'config' if selected_config == runtime['image_id'] else 'selected_manifest'
    runtime['selected_descriptor'] = descriptors[runtime['platform_children'][runtime['platform']]]
    return configs


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
    runtime["platform_configs"] = verify_platform_configs(runtime, reference=args.reference,
        source_revision=args.source_revision, source_snapshot=args.source_snapshot,
        version=args.version, index_data=args.index.read_bytes(), fixture=FIXTURE_POLICY.is_file(),
        image_output=args.image_inspect.read_text())
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
