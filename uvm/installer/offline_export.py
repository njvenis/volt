"""Bounded original OCI authentication transport for the fixed verifier policy.

Filesystem omissions come ONLY from executable manifests' typed layer edges.
Every config, attachment and proof edge is mandatory, even when its digest is
also named by a filesystem layer. No failed fetch can become an omission.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from uvm.installer.offline_artifacts import (ROOT, PACKAGE, MAX_FILES, MAX_MEMBER, MAX_TOTAL,
    PROFILE, canonical, digest, pairs, native_platform)

PACKAGE_ROOT = Path('/package')
INDEX_TYPES = frozenset(('application/vnd.oci.image.index.v1+json',
    'application/vnd.docker.distribution.manifest.list.v2+json'))
MANIFEST_TYPES = frozenset(('application/vnd.oci.image.manifest.v1+json',
    'application/vnd.docker.distribution.manifest.v2+json'))
CONFIG_TYPES = frozenset(('application/vnd.oci.image.config.v1+json',
    'application/vnd.docker.container.image.v1+json'))
PROOF_TYPES = frozenset(('application/vnd.dev.sigstore.bundle.v0.3+json', 'application/vnd.in-toto+json'))
FILESYSTEM_TYPES = frozenset(('application/vnd.oci.image.layer.v1.tar',
    'application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.oci.image.layer.v1.tar+zstd',
    'application/vnd.docker.image.rootfs.diff.tar', 'application/vnd.docker.image.rootfs.diff.tar.gzip'))
EMPTY_CONFIG = 'application/vnd.oci.empty.v1+json'


class FixtureRegistry:
    """Only the baked verifier fixture's owned loopback repositories."""
    def __init__(self, reference: str):
        match = re.fullmatch(r'127\.0\.0\.1:46150/(volt|volt-installer-verifier)@sha256:([0-9a-f]{64})', reference)
        if match is None:
            raise ValueError('offline exporter repository is outside the independently baked fixture')
        self.repository = match[1]
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, *_args, **_kwargs):
                raise ValueError('owned fixture registry redirect refused')
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def read(self, category: str, value: str, *, optional_404: bool = False) -> bytes | None:
        if category not in ('manifests', 'blobs', 'referrers') or not re.fullmatch(
                r'(?:sha256:[0-9a-f]{64}|sha256-[0-9a-f]{64})', value):
            raise ValueError('offline registry object path is not fixed/content-addressed')
        request = Request('http://127.0.0.1:46150/v2/' + self.repository + '/' + category + '/' + value,
            headers={'Accept': ','.join(sorted(INDEX_TYPES | MANIFEST_TYPES)) + ',application/json'})
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(MAX_MEMBER + 1)
        except HTTPError as exc:
            if optional_404 and exc.code == 404:
                return None
            raise ValueError('mandatory original offline registry object fetch failed') from None
        if len(raw) > MAX_MEMBER:
            raise ValueError('offline registry metadata/proof object exceeds bound')
        return raw


class ProductionRegistry:
    """Public read-only original metadata from the two fixed official GHCR repos."""
    def __init__(self,reference):
        from urllib.parse import urlsplit
        m=re.fullmatch(r'ghcr\.io/(njvenis/(?:volt|volt-installer-verifier))@sha256:[0-9a-f]{64}',reference)
        if m is None:raise ValueError('production original export requires a fixed official GHCR digest')
        self.repository=m[1];self.token=None
        class Redirect(HTTPRedirectHandler):
            def redirect_request(self,req,fp,code,msg,headers,newurl):
                t=urlsplit(newurl)
                if ('/blobs/' not in req.full_url or t.scheme!='https'or t.username or t.password
                        or t.port not in(None,443)or not t.hostname or not t.hostname.endswith('.githubusercontent.com')):
                    raise ValueError('production registry redirect denied')
                return Request(newurl,headers={'Accept':'application/octet-stream'})
        self.opener=build_opener(ProxyHandler({}),Redirect())
    def read(self,category,value,*,optional_404=False):
        from urllib.parse import urlencode
        if category not in('manifests','blobs','referrers')or re.fullmatch(r'(?:sha256:[0-9a-f]{64}|sha256-[0-9a-f]{64})',value)is None:
            raise ValueError('production registry path is not closed/content-addressed')
        headers={'Accept':','.join(sorted(INDEX_TYPES|MANIFEST_TYPES))+',application/json'}
        if self.token:headers['Authorization']='Bearer '+self.token
        url='https://ghcr.io/v2/'+self.repository+'/'+category+'/'+value
        try:response=self.opener.open(Request(url,headers=headers),timeout=20)
        except HTTPError as error:
            if optional_404 and error.code==404:return None
            if error.code!=401 or self.token is not None:raise ValueError('production original metadata request failed')from None
            # Ignore candidate WWW-Authenticate destinations; use fixed GHCR public pull.
            with self.opener.open(Request('https://ghcr.io/token?'+urlencode({'scope':'repository:'+self.repository+':pull'})),timeout=20)as auth:
                raw=auth.read(65537)
            if len(raw)>65536:raise ValueError('GHCR pull token exceeds bound')
            record=json.loads(raw);token=record.get('token')or record.get('access_token')
            if type(token)is not str or re.fullmatch(r'[A-Za-z0-9._~+/-]+=*',token)is None:raise ValueError('GHCR public pull token malformed')
            self.token=token;headers['Authorization']='Bearer '+token
            try:response=self.opener.open(Request(url,headers=headers),timeout=20)
            except HTTPError as retry:
                if optional_404 and retry.code==404:return None
                raise ValueError('production original authenticated request failed')from None
        with response:raw=response.read(MAX_MEMBER+1)
        if len(raw)>MAX_MEMBER:raise ValueError('production original metadata exceeds bound')
        return raw


class MetadataLayout:
    def __init__(self, registry, reference: str):
        self.registry, self.reference = registry, reference
        self.blobs = {}
        self.omitted_filesystem = set()
        self.expanded = set()

    def mandatory(self, descriptor: dict, *, category: str = 'blobs') -> bytes:
        if (not isinstance(descriptor, dict) or not isinstance(descriptor.get('digest'), str)
                or re.fullmatch(r'sha256:[0-9a-f]{64}', descriptor['digest']) is None
                or type(descriptor.get('size')) is not int or not 0 <= descriptor['size'] <= MAX_MEMBER
                or not isinstance(descriptor.get('mediaType'), str)):
            raise ValueError('required original OCI descriptor is malformed or exceeds bound')
        value = descriptor['digest']
        raw = self.blobs.get(value)
        if raw is None:
            raw = self.registry.read(category, value)
        if raw is None or digest(raw) != value or len(raw) != descriptor['size']:
            raise ValueError('mandatory original OCI object digest/size differs')
        self.blobs[value] = raw
        self.omitted_filesystem.discard(value)
        if len(self.blobs) > MAX_FILES or sum(map(len, self.blobs.values())) > MAX_TOTAL:
            raise ValueError('original offline metadata graph exceeds closure bound')
        return raw

    def document(self, descriptor: dict, *, role: str) -> dict:
        if role not in ('executable', 'proof'):
            raise ValueError('original graph role is not independently established')
        raw = self.mandatory(descriptor, category='manifests')
        document = json.loads(raw, object_pairs_hook=pairs)
        if (not isinstance(document, dict) or document.get('schemaVersion') != 2
                or document.get('mediaType') != descriptor['mediaType']):
            raise ValueError('original OCI graph media/schema differs')
        # A referrer/proof role is assigned BEFORE traversal. Native-looking
        # config cannot upgrade it. Explicit artifacts/subjects also never gain
        # omission permission even if referenced from a native platform row.
        if document.get('artifactType') is not None or document.get('subject') is not None:
            role = 'proof'
        expansion = (descriptor['digest'], role)
        if expansion in self.expanded:
            return document
        self.expanded.add(expansion)
        media = document['mediaType']
        if media in INDEX_TYPES:
            children = document.get('manifests')
            if not isinstance(children, list) or not 1 <= len(children) <= 64:
                raise ValueError('original OCI index has an unsupported child inventory')
            seen = set()
            for child in children:
                if not isinstance(child, dict):
                    raise ValueError('original OCI index child descriptor is malformed')
                if child.get('digest') in seen:
                    raise ValueError('original OCI index repeats a graph object')
                seen.add(child.get('digest'))
                platform = child.get('platform')
                child_role = ('executable' if role == 'executable' and native_platform(platform) is not None else 'proof')
                self.document(child, role=child_role)
        elif media in MANIFEST_TYPES:
            config = document.get('config')
            raw_config = self.mandatory(config)
            config_value = json.loads(raw_config, object_pairs_hook=pairs)
            if not isinstance(config_value, dict):
                raise ValueError('original OCI config is not an object')
            executable = role == 'executable' and config['mediaType'] in CONFIG_TYPES and (
                config_value.get('os'), config_value.get('architecture')) in (('linux', 'amd64'), ('linux', 'arm64'))
            if config['mediaType'] not in CONFIG_TYPES | {EMPTY_CONFIG}:
                raise ValueError('unknown original OCI config type cannot be omitted')
            layers = document.get('layers')
            if not isinstance(layers, list) or not 1 <= len(layers) <= 256:
                raise ValueError('original OCI layer inventory is unsupported')
            for layer in layers:
                if not isinstance(layer, dict):
                    raise ValueError('original OCI layer descriptor is malformed')
                if executable and layer.get('mediaType') in FILESYSTEM_TYPES:
                    value = layer.get('digest')
                    if (not isinstance(value, str) or re.fullmatch(r'sha256:[0-9a-f]{64}', value) is None
                            or type(layer.get('size')) is not int or not 0 <= layer['size'] <= 32 * 1024**3):
                        raise ValueError('original filesystem layer descriptor is malformed')
                    if value not in self.blobs:
                        self.omitted_filesystem.add(value)
                elif layer.get('mediaType') in PROOF_TYPES or (role == 'proof' and layer.get('mediaType') in FILESYSTEM_TYPES):
                    self.mandatory(layer)
                else:
                    raise ValueError('unknown original OCI layer type cannot be omitted')
        else:
            raise ValueError('unknown original OCI graph type cannot be omitted')
        return document

    def collect(self) -> dict:
        value = self.reference.split('@')[1]
        raw = self.registry.read('manifests', value)
        if raw is None or digest(raw) != value:
            raise ValueError('original OCI root differs from externally expected digest')
        media = json.loads(raw, object_pairs_hook=pairs).get('mediaType')
        root = {'digest': value, 'size': len(raw), 'mediaType': media}
        self.blobs[value] = raw
        document = self.document(root, role='executable')
        referrers = self.registry.read('referrers', value, optional_404=True)
        if referrers is None:
            referrers = self.registry.read('manifests', 'sha256-' + value[7:], optional_404=True)
        if referrers is None:
            raise ValueError('original required authentication referrers are missing')
        refs = json.loads(referrers, object_pairs_hook=pairs)
        if (not isinstance(refs, dict) or refs.get('schemaVersion') != 2 or refs.get('mediaType') not in INDEX_TYPES
                or not isinstance(refs.get('manifests'), list) or not 1 <= len(refs['manifests']) <= 64):
            raise ValueError('original authentication referrer index is malformed')
        self.blobs[digest(referrers)] = referrers
        for descriptor in refs['manifests']:
            attachment = self.document(descriptor, role='proof')
            if (attachment.get('artifactType') not in PROOF_TYPES
                    or not isinstance(attachment.get('subject'), dict)
                    or any(attachment['subject'].get(key) != root[key] for key in ('digest', 'size', 'mediaType'))):
                raise ValueError('original authentication attachment has another subject/type')
        annotations = {'kind': 'dev.cosignproject.cosign/imageIndex' if media in INDEX_TYPES else 'dev.cosignproject.cosign/image'}
        transport = {**root, 'annotations': annotations}
        if media in MANIFEST_TYPES:
            transport['artifactType'] = document['config']['mediaType']
        return {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json', 'manifests': [transport]}


def export_originals(args, *, fixture: bool) -> dict:
    if not fixture:
        from uvm.installer.sigstore_policy import identity
        identity(args.signer,args.issuer)
        if (re.fullmatch(r'ghcr\.io/njvenis/volt@sha256:[0-9a-f]{64}',args.reference)is None
                or re.fullmatch(r'ghcr\.io/njvenis/volt-installer-verifier@sha256:[0-9a-f]{64}',args.expected_verifier_reference)is None):
            raise ValueError('production export runtime/verifier roles must retain fixed official repositories')
    root = ROOT
    from uvm.installer.offline_artifacts import _directory
    from uvm.installer.lock import _bounded_file
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _directory(descriptor)
        initial_root = os.fstat(descriptor)
    finally: os.close(descriptor)
    if any(root.iterdir()):
        raise ValueError('offline export requires a fresh empty private staging directory')
    from uvm.installer.admission import platform_children
    index = args.index.read_bytes()
    children = platform_children(index, args.reference)
    references = {'runtime-index': args.reference, 'verifier': args.expected_verifier_reference,
        **{'runtime-' + platform.split('/')[1]: args.reference.split('@')[0] + '@' + value
            for platform, value in children.items()}}
    files = {}
    def write(name, raw):
        if len(files) >= MAX_FILES or sum(row['bytes'] for row in files.values()) + len(raw) > MAX_TOTAL:
            raise ValueError('original offline export exceeds closure inventory bound')
        parts = name.split('/')
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            _directory(descriptor)
            current_root = os.fstat(descriptor)
            if (current_root.st_dev, current_root.st_ino) != (initial_root.st_dev, initial_root.st_ino):
                raise ValueError('offline export staging directory identity changed')
            for part in parts[:-1]:
                try: os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError: pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor); descriptor = child; _directory(descriptor)
            output = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
            with os.fdopen(output, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        files[name] = {'bytes': len(raw), 'sha256': digest(raw)}
    for name in sorted(PACKAGE):
        source = PACKAGE_ROOT / name
        limit = 64 * MAX_MEMBER if name == 'installer.bundle.tar.gz' else MAX_MEMBER
        write('package/' + name, _bounded_file(source, limit, private=False))
    for name, reference in references.items():
        layout = MetadataLayout((FixtureRegistry if fixture else ProductionRegistry)(reference), reference)
        transport = layout.collect()
        write(name + '/index.json', canonical(transport))
        write(name + '/oci-layout', canonical({'imageLayoutVersion': '1.0.0'}))
        for value, raw in sorted(layout.blobs.items()):
            write(name + '/blobs/sha256/' + value[7:], raw)
    release = {'version': args.version, 'signer': args.signer, 'issuer': args.issuer,
        'runtime_reference': args.reference, 'verifier_reference': args.expected_verifier_reference,
        'source_revision': args.source_revision, 'source_snapshot': args.source_snapshot,
        'bundle_sha256': files['package/installer.bundle.tar.gz']['sha256'],
        'launcher_sha256': files['package/launcher.sh']['sha256']}
    document = {'schema_version': 1, 'profile': PROFILE, 'release': release, 'files': files.copy()}
    write('closure.json', canonical(document))
    for current, _directories, _names in os.walk(root, topdown=False):
        descriptor = os.open(current, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    return document
