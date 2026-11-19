"""Independently trusted, pre-runtime verifier for the source-free installer."""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
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


def offline_bundle(args: argparse.Namespace):
    """Authenticate original cached bytes under ONLY this verifier's baked policy."""
    from uvm.installer.offline_artifacts import Closure, SIGNATURE_TYPE, SLSA_TYPE
    closure = Closure(fixture=FIXTURE_POLICY.is_file())
    expected = {'version': args.version or '0.1.0-rc.4', 'signer': args.signer, 'issuer': args.issuer,
        'verifier_reference': args.expected_verifier_reference}
    if (not isinstance(args.expected_verifier_reference, str)
            or any(closure.release[key] != value for key, value in expected.items())):
        raise ValueError('offline closure differs from the externally expected verifier/release/publisher')
    for path, name in ((args.bundle, 'installer.bundle.tar.gz'),
                       (args.bundle_signature, 'installer.bundle.sigstore.json')):
        if (path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BUNDLE_BYTES
                or path.read_bytes() != closure.files['package/' + name]):
            raise ValueError('offline package inputs differ from original cached signed bytes')
    closure.verify_statement(expected['verifier_reference'], SIGNATURE_TYPE, signer=args.signer, issuer=args.issuer)
    closure.verify_statement(expected['verifier_reference'], SLSA_TYPE, signer=args.signer, issuer=args.issuer)
    closure.verify_blob('launcher.sh', signer=args.signer, issuer=args.issuer)
    closure.verify_blob('installer.bundle.tar.gz', signer=args.signer, issuer=args.issuer)
    bundle = verify_closed_bundle(args.bundle, reference=closure.release['runtime_reference'])
    with tarfile.open(args.bundle, 'r:gz') as archive:
        launcher = [member for member in archive.getmembers() if PurePosixPath(member.name).name == 'launcher.sh'][0]
        if archive.extractfile(launcher).read(MAX_MEMBER_BYTES + 1) != closure.files['package/launcher.sh']:
            raise ValueError('original signed launcher differs from the signed bundle launcher')
        if FIXTURE_POLICY.is_file():
            manifest = [member for member in archive.getmembers() if PurePosixPath(member.name).name == 'manifest.json'][0]
            if json.load(archive.extractfile(manifest)).get('verifier_reference') != expected['verifier_reference']:
                raise ValueError('signed bundle differs from the independently expected verifier')
    if 'sha256:' + bundle['bundle_sha256'] != closure.release['bundle_sha256']:
        raise ValueError('signed offline bundle differs from declared original digest')
    closure.assert_unchanged()
    if getattr(args, 'require_installed_pin', False):
        from uvm.installer.installed_artifacts import compare_journal_closure, validate_live_cache
        from uvm.installer.lock import _bounded_file
        from uvm.installer.offline_artifacts import pairs
        info = json.loads(_bounded_file(Path('/run/volt-selected-journal/instance.json'),
            1024 * 1024, private=True), object_pairs_hook=pairs)
        compare_journal_closure(info, closure)
        validate_live_cache(info)
    return closure, bundle


def verify_offline(args: argparse.Namespace) -> dict:
    """Run the complete source/platform policy on freshly authenticated originals."""
    from uvm.installer.offline_artifacts import SIGNATURE_TYPE, RUNTIME_TYPE
    closure, bundle = offline_bundle(args)
    for key, value in {'runtime_reference': args.reference, 'source_revision': args.source_revision,
            'source_snapshot': args.source_snapshot, 'version': args.version}.items():
        if closure.release[key] != value:
            raise ValueError('offline closure differs from the exact selected source/image/version')
    index = closure.blob(args.reference.split('@')[1])
    if (args.index.is_symlink() or not args.index.is_file() or args.index.stat().st_size > MAX_MEMBER_BYTES
            or args.index.read_bytes() != index or args.image_inspect.is_symlink()
            or not args.image_inspect.is_file() or args.image_inspect.stat().st_size > MAX_MEMBER_BYTES):
        raise ValueError('offline index or actual selected engine observation differs')
    from uvm.installer.admission import platform_children
    children = platform_children(index, args.reference)
    for reference in (args.reference, *(args.reference.split('@')[0] + '@' + child for child in children.values())):
        closure.verify_statement(reference, SIGNATURE_TYPE, signer=args.signer, issuer=args.issuer)
    # Preserve the EXACT successful cryptographic DSSE output. Re-encoding a
    # matching sidefile or a decoded statement is never verification evidence.
    provenance = closure.verify_envelope(args.reference, RUNTIME_TYPE, signer=args.signer, issuer=args.issuer)
    image_output = args.image_inspect.read_text()
    runtime = verify_runtime(image_output=image_output, index_data=index, provenance_output=provenance,
        reference=args.reference, source_revision=args.source_revision, source_snapshot=args.source_snapshot,
        version=args.version, platform=args.platform, bundle_sha256=bundle['bundle_sha256'])

    def cached_document(kind, value):
        if kind not in ('manifests', 'blobs'):
            raise ValueError('offline child/config request is outside the fixed graph')
        for layout in ('runtime-index', 'runtime-amd64', 'runtime-arm64'):
            name = layout + '/blobs/sha256/' + value.removeprefix('sha256:')
            if name in closure.files:
                return closure.blob(value, layout=layout)
        raise ValueError('original offline child/config graph object is missing')

    runtime['platform_configs'] = verify_platform_configs(runtime, reference=args.reference,
        source_revision=args.source_revision, source_snapshot=args.source_snapshot, version=args.version,
        index_data=index, fixture=FIXTURE_POLICY.is_file(), image_output=image_output, fetch=cached_document)
    closure.assert_unchanged()
    receipt = {'schema_version': 1, 'profile': 'volt_verified_installer_v1',
        'closure_sha256': closure.hash, 'launcher_sha256': closure.release['launcher_sha256'],
        'bundle_sha256': closure.release['bundle_sha256'],
        'verifier_reference': closure.release['verifier_reference'], 'signer': args.signer, 'issuer': args.issuer}
    return {'bundle': bundle, 'runtime': runtime, 'offline_artifacts': receipt}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--bundle-signature", type=Path, required=True)
    parser.add_argument("--bundle-only", action="store_true")
    offline_mode = parser.add_mutually_exclusive_group()
    offline_mode.add_argument('--offline-artifacts', action='store_true',
        help='reverify the fixed original closure mount without registry access; not a trust-policy selector')
    offline_mode.add_argument('--export-offline-artifacts', action='store_true',
        help='export original metadata-only proof transport, then freshly reverify it; never publish installed state')
    parser.add_argument('--expected-verifier-reference')
    parser.add_argument('--bind-initial-request', action='store_true')
    parser.add_argument('--publish-cache', action='store_true')
    parser.add_argument('--cache-state')
    parser.add_argument('--cache-stage-name')
    parser.add_argument('--inspect-cache-intent', action='store_true')
    parser.add_argument('--require-installed-pin', action='store_true')
    for name in ("image-inspect", "index", "output-dir"):
        parser.add_argument("--" + name, type=Path)
    for name in ("signer", "issuer"):
        parser.add_argument("--" + name, required=True)
    for name in ("reference", "source-revision", "source-snapshot", "version", "platform"):
        parser.add_argument("--" + name)
    args = parser.parse_args()
    try:
        if args.inspect_cache_intent:
            if (not args.bundle_only or args.offline_artifacts or args.export_offline_artifacts
                    or args.publish_cache or args.bind_initial_request or args.require_installed_pin
                    or args.cache_stage_name is not None or any(value is None for value in
                        (args.reference, args.expected_verifier_reference, args.source_revision,
                         args.source_snapshot, args.version, args.platform, args.cache_state))):
                parser.error('installed cache intent is fixed comparison data only')
            from uvm.installer.installed_artifacts import journal_intent
            from uvm.installer.lock import _bounded_file
            from uvm.installer.offline_artifacts import pairs
            info = json.loads(_bounded_file(Path('/run/volt-selected-journal/instance.json'),
                1024 * 1024, private=True), object_pairs_hook=pairs)
            intent = journal_intent(info, canonical_state=args.cache_state, reference=args.reference,
                verifier_reference=args.expected_verifier_reference, source_revision=args.source_revision,
                source_snapshot=args.source_snapshot, version=args.version, platform=args.platform)
            for key, value in intent.items(): print(str(key) + '=' + str(value))
            return 0
        if args.require_installed_pin and not args.offline_artifacts:
            parser.error('installed journal comparison requires fresh original cached verification')
        if args.bind_initial_request and (not args.offline_artifacts or args.bundle_only):
            parser.error('initial request binding requires fresh complete cached verification')
        if args.publish_cache:
            if not (args.offline_artifacts or args.export_offline_artifacts) or args.bundle_only:
                parser.error('installed cache publication requires complete fresh original-graph verification')
            if args.cache_state is None or args.cache_stage_name is None:
                parser.error('cache publication requires the canonical selected state and exact staging intent')
        elif (args.cache_state is not None or args.cache_stage_name is not None) and not args.export_offline_artifacts:
            parser.error('cache destination data cannot select another verifier action')
        if args.export_offline_artifacts and (args.cache_state is not None or args.cache_stage_name is not None):
            if args.cache_state is None or args.cache_stage_name is None:
                parser.error('durable initial staging requires its canonical state and exact staging intent')
        if args.bundle_only:
            if args.export_offline_artifacts:
                parser.error('offline artifact export requires complete normal graph admission first')
            if args.offline_artifacts:
                closure, bundle = offline_bundle(args)
                reference, digest = closure.release['runtime_reference'], bundle['bundle_sha256']
            else:
                if args.expected_verifier_reference is not None:
                    parser.error('offline verifier expectation cannot select online verification policy')
                reference, digest = discover_signed_reference(args.bundle, args.bundle_signature, args.signer, args.issuer)
            print(f"reference={reference}\nbundle_sha256={digest}")
            return 0
        if any(getattr(args, key) is None for key in
               ("reference", "source_revision", "source_snapshot", "version", "platform")):
            parser.error("full graph verification requires reference, source, version, and platform metadata")
        if any(getattr(args, key.replace("-", "_")) is None for key in
               ("image-inspect", "index", "output-dir")):
            parser.error("full graph verification requires image inspection, index, and output paths")
        args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not (args.offline_artifacts or args.export_offline_artifacts) and args.expected_verifier_reference is not None:
            parser.error('offline verifier expectation cannot select online verification policy')
        if args.export_offline_artifacts:
            if args.expected_verifier_reference is None:
                parser.error('offline artifact export requires the independent external verifier pin')
            verify(args)
            from uvm.installer.offline_export import export_originals
            export_originals(args, fixture=FIXTURE_POLICY.is_file())
            result = verify_offline(args)
            if args.cache_state is not None:
                from uvm.installer.installed_artifacts import durable_stage
                durable_stage(args.cache_state, args.cache_stage_name)
        else:
            result = verify_offline(args) if args.offline_artifacts else verify(args)
        if args.bind_initial_request:
            from uvm.installer.lock import INITIAL_REQUEST, MAX_REQUEST, _bounded_file
            from uvm.installer.offline_artifacts import digest, pairs
            raw = _bounded_file(INITIAL_REQUEST, MAX_REQUEST, private=True)
            request = json.loads(raw, object_pairs_hook=pairs)
            if (not isinstance(request, dict) or set(request) != {'schema_version', 'profile', 'arguments', 'setup_sha256'}
                    or type(request['schema_version']) is not int or request['schema_version'] != 1
                    or request['profile'] != 'volt_local_runtime_init_v1' or not isinstance(request['arguments'], dict)
                    or json.loads(request['arguments']['admitted_installer_json'], object_pairs_hook=pairs)
                        != result['offline_artifacts']):
                raise ValueError('initial request differs from the freshly authenticated cache admission')
            with tarfile.open(args.bundle, 'r:gz') as archive:
                setup = [item for item in archive.getmembers() if PurePosixPath(item.name).name == 'setup.py'][0]
                if request['setup_sha256'] != digest(archive.extractfile(setup).read(MAX_MEMBER_BYTES + 1)):
                    raise ValueError('initial request differs from the exact signed setup implementation')
            result['initial_request_sha256'] = digest(raw)
        if args.publish_cache:
            from uvm.installer.installed_artifacts import publish_cache
            from uvm.installer.lock import _bounded_file
            from uvm.installer.offline_artifacts import pairs
            observation = json.loads(_bounded_file(Path('/run/volt-cache-observation/mounts.json'),
                8 * 1024 * 1024, private=True), object_pairs_hook=pairs)
            published = publish_cache(args.cache_state, args.cache_stage_name, result['offline_artifacts'], observation)
            print(json.dumps({'installed_cache_publication': published}, sort_keys=True), file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, tarfile.TarError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
