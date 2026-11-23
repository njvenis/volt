"""Read the fixed original authentication closure; never trust a cached pass."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path('/run/volt-offline-artifacts')
PROFILE = 'volt_offline_artifacts_v1'
SIGNATURE_TYPE = 'https://sigstore.dev/cosign/sign/v1'
SLSA_TYPE = 'https://slsa.dev/provenance/v1'
RUNTIME_TYPE = 'https://volt.dev/attestation/easy-install/v1'
LAYOUTS = ('runtime-index', 'runtime-amd64', 'runtime-arm64', 'verifier')
PACKAGE = frozenset(('launcher.sh', 'launcher.sigstore.json',
    'installer.bundle.tar.gz', 'installer.bundle.sigstore.json'))
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
IDENTITY_FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
    'st_size', 'st_mtime_ns', 'st_ctime_ns')
MAX_FILES = 4096
MAX_TOTAL = 128 * 1024 * 1024
MAX_MEMBER = 1024 * 1024


def canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def digest(raw: bytes) -> str:
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate offline artifact member')
        result[key] = value
    return result


def identity(info):
    return tuple(getattr(info, name) for name in IDENTITY_FIELDS)


def _directory(fd: int) -> None:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('offline artifact directory custody differs')


def _read(root: Path, relative: str, limit: int) -> tuple[bytes, tuple]:
    parts = relative.split('/')
    if any(not part or part in ('.', '..') for part in parts) or relative.startswith('/'):
        raise ValueError('offline artifact path is not normalized')
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _directory(directory)
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
            _directory(directory)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                    or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_size > limit):
                raise ValueError('offline artifact file custody or bound differs')
            raw = stream.read(limit + 1)
            current = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
            if (len(raw) != before.st_size or identity(before) != identity(current)
                    or identity(before) != identity(os.fstat(stream.fileno()))):
                raise ValueError('offline artifact changed while read')
            return raw, identity(before)
    finally:
        os.close(directory)


def _allowed(name: str) -> bool:
    parts = name.split('/')
    if len(parts) == 2 and parts[0] == 'package':
        return parts[1] in PACKAGE
    return parts[0] in LAYOUTS and (
        len(parts) == 2 and parts[1] in ('index.json', 'oci-layout') or
        len(parts) == 4 and parts[1:3] == ['blobs', 'sha256']
        and re.fullmatch(r'[0-9a-f]{64}', parts[3]) is not None)


class Closure:
    """Fixed-mount original bytes, followed by fresh cryptographic verification."""

    def __init__(self, *, fixture: bool | None, custody_root: Path | None = None):
        if custody_root is not None and fixture is not None:
            raise ValueError('cryptographic offline admission uses only its fixed original-closure mount')
        self.root = ROOT if custody_root is None else custody_root
        # True/False are selected ONLY by the verifier's baked policy. None is
        # a custody-only runtime reader and can never perform crypto admission.
        self.fixture = fixture
        raw, initial = _read(self.root, 'closure.json', MAX_MEMBER)
        document = json.loads(raw, object_pairs_hook=pairs)
        if (not isinstance(document, dict) or set(document) != {'schema_version', 'profile', 'release', 'files'}
                or type(document['schema_version']) is not int or document['schema_version'] != 1
                or document['profile'] != PROFILE or canonical(document) != raw):
            raise ValueError('closed canonical offline artifact inventory required')
        release = document['release']
        fields = {'version', 'signer', 'issuer', 'verifier_reference', 'runtime_reference',
            'source_revision', 'source_snapshot', 'bundle_sha256', 'launcher_sha256'}
        prefix = (re.escape('127.0.0.1:46150/') if fixture is True else
            re.escape('ghcr.io/njvenis/') if fixture is False else
            r'(?:127\.0\.0\.1:46150/|ghcr\.io/njvenis/)')
        if (not isinstance(release, dict) or set(release) != fields or release['version'] != '0.1.0-rc.4'
                or any(not isinstance(release[key], str) for key in fields)
                or re.fullmatch(r'[0-9a-f]{40}', release['source_revision']) is None
                or any(DIGEST.fullmatch(release[key]) is None for key in
                    ('source_snapshot', 'bundle_sha256', 'launcher_sha256'))
                or re.fullmatch(prefix + r'volt@sha256:[0-9a-f]{64}', release['runtime_reference']) is None
                or re.fullmatch(prefix + r'volt-installer-verifier@sha256:[0-9a-f]{64}', release['verifier_reference']) is None):
            raise ValueError('offline release declaration is malformed')
        members = document['files']
        if not isinstance(members, dict) or not 1 <= len(members) <= MAX_FILES:
            raise ValueError('offline artifact member count differs')
        self.files, self.identities = {}, {'closure.json': initial}
        total = 0
        for name, record in members.items():
            if (not _allowed(name) or not isinstance(record, dict) or set(record) != {'bytes', 'sha256'}
                    or type(record['bytes']) is not int or record['bytes'] < 0
                    or not isinstance(record['sha256'], str) or DIGEST.fullmatch(record['sha256']) is None):
                raise ValueError('offline artifact file inventory is not closed')
            limit = 64 * MAX_MEMBER if name == 'package/installer.bundle.tar.gz' else MAX_MEMBER
            content, observed = _read(self.root, name, limit)
            if len(content) != record['bytes'] or digest(content) != record['sha256']:
                raise ValueError('original offline artifact hash/size differs')
            if '/blobs/sha256/' in name and name.rsplit('/', 1)[1] != record['sha256'][7:]:
                raise ValueError('offline OCI blob differs from its content address')
            total += len(content)
            if total > MAX_TOTAL:
                raise ValueError('offline artifact closure exceeds total bound')
            self.files[name], self.identities[name] = content, observed
        if any('package/' + name not in self.files for name in PACKAGE):
            raise ValueError('original signed package closure is incomplete')
        self.document, self.release = document, release
        self.hash = digest(raw)
        self._walk()
        self._layouts()
        if (digest(self.files['package/launcher.sh']) != release['launcher_sha256']
                or digest(self.files['package/installer.bundle.tar.gz']) != release['bundle_sha256']):
            raise ValueError('offline original package differs from declared release')

    def _walk(self):
        observed = set()
        observed_directories = set()
        expected_directories = {str(parent) for name in self.files
            for parent in Path(name).parents if str(parent) != '.'}
        count = 0
        for current, directories, files in os.walk(self.root, followlinks=False):
            for name in directories:
                path = Path(current) / name
                observed_directories.add(str(path.relative_to(self.root)))
                info = path.lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o700):
                    raise ValueError('offline artifact directory is linked or unsafe')
            for name in files:
                observed.add(str((Path(current) / name).relative_to(self.root)))
            count += len(directories) + len(files)
            if count > MAX_FILES + 64:
                raise ValueError('offline artifact directory inventory exceeds bound')
        if observed != set(self.files) | {'closure.json'} or observed_directories != expected_directories:
            raise ValueError('offline artifact closure contains extra or missing files')

    def _layouts(self):
        self.references = {}
        for name in LAYOUTS:
            layout = json.loads(self.files[name + '/oci-layout'], object_pairs_hook=pairs)
            index = json.loads(self.files[name + '/index.json'], object_pairs_hook=pairs)
            if layout != {'imageLayoutVersion': '1.0.0'} or len(index.get('manifests', [])) != 1:
                raise ValueError('offline OCI layout has an unexpected root inventory')
            descriptor = index['manifests'][0]
            expected = self.release['verifier_reference' if name == 'verifier' else 'runtime_reference']
            if name in ('runtime-amd64', 'runtime-arm64'):
                parent = self.blob(self.release['runtime_reference'].split('@')[1], layout='runtime-index')
                platform = {'os': 'linux', 'architecture': name.split('-')[1]}
                rows = [item for item in json.loads(parent)['manifests'] if item.get('platform') == platform]
                if len(rows) != 1:
                    raise ValueError('offline runtime index lacks an exact native child')
                expected = expected.split('@')[0] + '@' + rows[0]['digest']
            if descriptor.get('digest') != expected.split('@')[1]:
                raise ValueError('offline layout root differs from expected index/child identity')
            content = self.blob(descriptor['digest'], layout=name)
            document = json.loads(content, object_pairs_hook=pairs)
            if (type(descriptor.get('size')) is not int or descriptor['size'] != len(content)
                    or descriptor.get('mediaType') != document.get('mediaType')):
                raise ValueError('offline layout root descriptor size differs')
            self.references[expected] = name

    def blob(self, value: str, *, layout: str = 'runtime-index') -> bytes:
        if not isinstance(value, str) or DIGEST.fullmatch(value) is None or layout not in LAYOUTS:
            raise ValueError('offline graph object identity is invalid')
        try:
            return self.files[layout + '/blobs/sha256/' + value[7:]]
        except KeyError:
            raise ValueError('original offline authentication graph object is missing') from None

    def assert_unchanged(self):
        for name, observed in self.identities.items():
            limit = 64 * MAX_MEMBER if name == 'package/installer.bundle.tar.gz' else MAX_MEMBER
            _, current = _read(self.root, name, limit)
            if current != observed:
                raise ValueError('offline artifact closure changed during verification')
        self._walk()

    def verify_blob(self, name: str, *, signer: str, issuer: str) -> None:
        if name not in ('launcher.sh', 'installer.bundle.tar.gz'):
            raise ValueError('offline blob is outside the original signed package')
        if signer != self.release['signer'] or issuer != self.release['issuer']:
            raise ValueError('offline release differs from externally expected publisher policy')
        if self.fixture is None:
            raise ValueError('custody-only readers cannot authenticate artifacts')
        signature = 'launcher.sigstore.json' if name == 'launcher.sh' else 'installer.bundle.sigstore.json'
        trust = Path('/usr/local/share/volt-verifier')
        from uvm.installer.sigstore_policy import keyless_arguments
        policy = (['--key',str(trust/'fixture.pub'),'--trusted-root',str(trust/'trusted-root.json')]
            if self.fixture is True else keyless_arguments(signer,issuer))
        result = subprocess.run(['/usr/local/bin/cosign', 'verify-blob', *policy, '--bundle', str(self.root / 'package' / signature),
            str(self.root / 'package' / name)], stdin=subprocess.DEVNULL, capture_output=True, text=True,
            env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp'}, timeout=90)
        if result.returncode:
            raise ValueError('offline original blob signature/proof verification failed: ' + result.stderr[-1200:].strip())
        self.assert_unchanged()

    def verify_statement(self, reference: str, predicate: str, *, signer: str, issuer: str) -> dict:
        output = self.verify_envelope(reference, predicate, signer=signer, issuer=issuer)
        return json.loads(base64.b64decode(json.loads(output, object_pairs_hook=pairs)['payload'], validate=True),
            object_pairs_hook=pairs)

    def verify_envelope(self, reference: str, predicate: str, *, signer: str, issuer: str) -> str:
        """Bind only the payload returned by THIS successful crypto execution."""
        if reference not in self.references or predicate not in (SIGNATURE_TYPE, SLSA_TYPE, RUNTIME_TYPE):
            raise ValueError('offline verification target/type is outside the fixed graph')
        if signer != self.release['signer'] or issuer != self.release['issuer']:
            raise ValueError('offline release differs from externally expected publisher policy')
        if self.fixture is None:
            raise ValueError('custody-only readers cannot authenticate artifacts')
        # These are baked independent verifier inputs, never closure inputs.
        trust = Path('/usr/local/share/volt-verifier')
        from uvm.installer.sigstore_policy import keyless_arguments
        policy = (['--key',str(trust/'fixture.pub'),'--trusted-root',str(trust/'trusted-root.json')]
            if self.fixture is True else keyless_arguments(signer,issuer))
        argv = ['/usr/local/bin/cosign', 'verify-attestation', '--type', predicate, *policy,
            '--local-image', str(self.root / self.references[reference])]
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp'}, timeout=90)
        if result.returncode:
            raise ValueError('offline original signature/proof verification failed: ' + result.stderr[-1200:].strip())
        if len(result.stdout.encode()) > 4 * MAX_MEMBER:
            raise ValueError('verified offline DSSE output exceeds bound')
        try:
            envelope = json.loads(result.stdout, object_pairs_hook=pairs)
            raw = base64.b64decode(envelope['payload'], validate=True)
            statement = json.loads(raw, object_pairs_hook=pairs)
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError('cryptographically verified offline DSSE output is malformed') from exc
        if (statement.get('predicateType') != predicate or len(statement.get('subject', [])) != 1
                or statement['subject'][0].get('digest') != {'sha256': reference.split('@sha256:')[1]}):
            raise ValueError('cryptographically verified offline DSSE subject/type differs from expected raw OCI digest')
        self.assert_unchanged()
        return result.stdout
