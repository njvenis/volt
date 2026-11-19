"""Strict installed-cache bookkeeping; NEVER a trust root or crypto substitute."""
from __future__ import annotations

import json
import errno
import os
from pathlib import Path
import re
import stat

from uvm.installer.admission import RC4_FILES
from uvm.installer.offline_artifacts import Closure, DIGEST, canonical, digest, pairs
from uvm.installer.lock import _bounded_file

SIGNER = 'https://github.com/njvenis/volt/.github/workflows/release-rc4.yml@refs/heads/main'
ISSUER = 'https://token.actions.githubusercontent.com'
PROFILE = 'volt_verified_installer_v1'
PIN_FIELDS = frozenset(('schema_version', 'profile', 'closure_sha256', 'launcher_sha256',
    'bundle_sha256', 'verifier_reference', 'signer', 'issuer'))
CACHE_PARENT = Path('/run/volt-cache-parent')
INITIAL_RECEIPT = Path('/run/volt-initialization-admission/receipt.json')
CURRENT_RECEIPT = Path('/run/volt-independent-admission/receipt.json')


def validate_pin(value: dict) -> dict:
    if (not isinstance(value, dict) or set(value) != PIN_FIELDS
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['profile'] != PROFILE or value['signer'] != SIGNER or value['issuer'] != ISSUER
            or any(not isinstance(value[key], str) or DIGEST.fullmatch(value[key]) is None
                for key in ('closure_sha256', 'launcher_sha256', 'bundle_sha256'))
            or not isinstance(value['verifier_reference'], str) or re.fullmatch(
                r'(?:ghcr\.io/njvenis/|127\.0\.0\.1:46150/)volt-installer-verifier@sha256:[0-9a-f]{64}',
                value['verifier_reference']) is None):
        raise ValueError('closed original installed-artifact pin is missing or contradicts fixed publisher expectations')
    return dict(value)


def validate_receipt(record: dict, *, admitted: dict, reference: str,
                     journal_pin: dict | None = None, initial_request: bytes | None = None,
                     cache_root: Path | None = None) -> dict:
    """Re-read exact bytes against a fresh external-verifier result under FD.

    This function cannot run Cosign, select a trust policy or admit unsigned
    data. The authenticated launcher obtains the new verifier result in the
    same invocation (under the held FD for established lifecycle operations).
    """
    fields = {'bundle', 'runtime', 'offline_artifacts'}
    if initial_request is not None: fields.add('initial_request_sha256')
    if not isinstance(record, dict) or set(record) != fields:
        raise ValueError('fresh independent verifier receipt is not the closed graph result')
    pin = validate_pin(record['offline_artifacts'])
    if journal_pin is not None and pin != validate_pin(journal_pin):
        raise ValueError('fresh cache verification contradicts the committed installed-artifact pin')
    if initial_request is not None and record['initial_request_sha256'] != digest(initial_request):
        raise ValueError('initial verifier receipt is stale or belongs to another exact initialization request')
    bundle, runtime = record['bundle'], record['runtime']
    if (not isinstance(bundle, dict) or set(bundle) != {'bundle_sha256', 'bundle_version', 'reference', 'files'}
            or bundle['bundle_sha256'] != pin['bundle_sha256'][7:] or bundle['bundle_version'] != admitted['version']
            or bundle['reference'] != reference or type(bundle['files']) is not int or bundle['files'] != len(RC4_FILES)
            or not isinstance(runtime, dict) or set(runtime) != {'image_id', 'image_id_kind', 'image_config_id',
                'selected_descriptor', 'platform', 'source_revision', 'source_snapshot', 'image_index_digest',
                'platform_children', 'platform_configs'}):
        raise ValueError('fresh receipt bundle/runtime inventory contradicts admitted initialization')
    mapping = {'image_id': 'id', 'image_id_kind': 'id_kind', 'image_config_id': 'image_config_id',
        'selected_descriptor': 'selected_descriptor', 'platform': 'platform',
        'source_revision': 'source_revision', 'source_snapshot': 'source_snapshot'}
    if (any(runtime[key] != admitted.get(target) for key, target in mapping.items())
            or runtime['image_index_digest'] != reference.split('@')[-1]
            or not isinstance(runtime['platform_children'], dict)
            or set(runtime['platform_children']) != {'linux/amd64', 'linux/arm64'}
            or not isinstance(runtime['platform_configs'], dict)
            or set(runtime['platform_configs']) != {'linux/amd64', 'linux/arm64'}
            or any(not isinstance(value, str) or DIGEST.fullmatch(value) is None
                for rows in (runtime['platform_children'], runtime['platform_configs']) for value in rows.values())
            or runtime['platform_configs'].get(runtime['platform']) != runtime['image_config_id']):
        raise ValueError('fresh cache receipt differs from exact selected image/source/platform admission')
    # None means file custody/inventory only. It CANNOT perform crypto and does
    # not derive fixture policy from journal/reference/signer strings.
    closure = Closure(fixture=None, custody_root=cache_root)
    from uvm.installer.admission import platform_children
    raw_index = closure.blob(reference.split('@')[-1])
    actual_children = platform_children(raw_index, reference)
    actual_configs = {}
    for platform, child in actual_children.items():
        manifest = json.loads(closure.blob(child, layout='runtime-' + platform.split('/')[1]), object_pairs_hook=pairs)
        config = manifest['config']['digest']
        closure.blob(config, layout='runtime-' + platform.split('/')[1])
        actual_configs[platform] = config
    descriptors = [row for row in json.loads(raw_index, object_pairs_hook=pairs)['manifests']
        if row.get('digest') == actual_children.get(runtime['platform'])]
    if (runtime['platform_children'] != actual_children or runtime['platform_configs'] != actual_configs
            or len(descriptors) != 1 or runtime['selected_descriptor'] != descriptors[0]):
        raise ValueError('fresh receipt index/children/config/selected-descriptor inventory differs from original cache bytes')
    release = closure.release
    expected = {'version': admitted['version'], 'runtime_reference': reference,
        'source_revision': admitted['source_revision'], 'source_snapshot': admitted['source_snapshot'],
        **{key: pin[key] for key in ('verifier_reference', 'bundle_sha256', 'launcher_sha256', 'signer', 'issuer')}}
    if closure.hash != pin['closure_sha256'] or any(release[key] != value for key, value in expected.items()):
        raise ValueError('actual original cache bytes/release differ from the fresh verifier result')
    closure.assert_unchanged()
    return pin


def initial_pin(request_raw: bytes, *, admitted: dict, reference: str, expected_pin: dict) -> dict:
    raw = _bounded_file(INITIAL_RECEIPT, 1024 * 1024, private=True)
    record = json.loads(raw, object_pairs_hook=pairs)
    pin = validate_receipt(record, admitted=admitted, reference=reference,
        initial_request=request_raw, journal_pin=expected_pin)
    if raw != _bounded_file(INITIAL_RECEIPT, 1024 * 1024, private=True):
        raise ValueError('fresh initial verifier receipt changed before identity creation')
    return pin


def committed_pin(info: dict) -> dict:
    if not isinstance(info, dict):
        raise ValueError('committed installer journal must be an object')
    if type(info.get('installer_contract_version')) is not int or info['installer_contract_version'] != 2:
        raise ValueError('established installer admission pin is missing; no cache adoption or backfill is permitted')
    pin = validate_pin(info.get('installer_admission'))
    validate_stage(info['host_instance_directory'], info.get('installer_cache_stage'))
    if (not isinstance(info.get('installer_initial_request_sha256'), str)
            or DIGEST.fullmatch(info['installer_initial_request_sha256']) is None
            or info.get('installer_phase') not in ('prepared', 'resources-created', 'started', 'awaiting-admin', 'ready')):
        raise ValueError('durable initial installer request/phase intent is missing')
    if not isinstance(info.get('installer_initial_files'), dict) or not 1 <= len(info['installer_initial_files']) <= 128:
        raise ValueError('committed initial file fingerprints are missing')
    return pin


def initial_inventory(root: Path) -> dict:
    result = {}
    for path in root.rglob('*'):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode): continue
        name = str(path.relative_to(root))
        if name in ('.install.lock', 'instance.json'): continue
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or len(result) >= 128:
            raise ValueError('initial private file inventory is linked, foreign, special or exceeds bound')
        raw = _bounded_file(path, 1024 * 1024, private=False)
        result[name] = {'sha256': digest(raw), 'mode': stat.S_IMODE(info.st_mode), 'bytes': len(raw)}
    return result


def verify_initial_inventory(root: Path, info: dict) -> None:
    committed_pin(info)
    for name, expected in info['installer_initial_files'].items():
        if (not isinstance(name, str) or name.startswith('/') or '..' in Path(name).parts
                or str(Path(name)) != name or not isinstance(expected, dict)
                or set(expected) != {'sha256', 'mode', 'bytes'} or type(expected['mode']) is not int
                or not 0 <= expected['mode'] <= 0o777
                or type(expected['bytes']) is not int or not 0 <= expected['bytes'] <= 1024 * 1024
                or not isinstance(expected['sha256'], str) or DIGEST.fullmatch(expected['sha256']) is None):
            raise ValueError('committed initial file fingerprint schema is malformed')
        path = root / name
        raw = _bounded_file(path, 1024 * 1024, private=False)
        if stat.S_IMODE(path.lstat().st_mode) != expected['mode']:
            raise ValueError('committed initial secret/configuration changed; no regeneration or repair is permitted')
        if name == '.env':
            # prepare_start already owns this durable CURRENT/PENDING
            # transition. Keep immutable fingerprints intact; do not invent a
            # second authority or learn an expected hash from observed bytes.
            current = info.get('env_sha256')
            pending = info.get('local_start_environment_pending_sha256')
            if (not isinstance(current, str) or re.fullmatch(r'[0-9a-f]{64}', current) is None
                    or pending is not None and (not isinstance(pending, str)
                        or re.fullmatch(r'[0-9a-f]{64}', pending) is None)
                    or digest(raw)[7:] not in {current, pending}):
                raise ValueError('committed current/pending start environment changed')
        elif digest(raw) != expected['sha256'] or len(raw) != expected['bytes']:
            raise ValueError('committed initial secret/configuration changed; no regeneration or repair is permitted')


def journal_intent(info: dict, *, canonical_state: str, reference: str, verifier_reference: str,
                   source_revision: str, source_snapshot: str, version: str, platform: str) -> dict:
    """Read comparison data only; this never authenticates a cache or permits init."""
    pin = committed_pin(info)
    admitted = info.get('image_admission')
    if (not isinstance(admitted, dict) or info.get('host_instance_directory') != canonical_state
            or info.get('image') != reference or pin['verifier_reference'] != verifier_reference
            or any(admitted.get(key) != value for key, value in {'source_revision': source_revision,
                'source_snapshot': source_snapshot, 'version': version, 'platform': platform}.items())
            or not isinstance(info.get('project'), str) or re.fullmatch(r'[a-z][a-z0-9_-]{0,62}', info['project']) is None
            or not isinstance(info.get('owner_token'), str) or re.fullmatch(r'[0-9a-f]{64}', info['owner_token']) is None):
        raise ValueError('selected journal cache intent contradicts canonical instance/image/source/publisher expectations')
    recovery = info.get('local_recovery_custody')
    initial = (info['installer_phase'] == 'prepared' and info.get('initialized') is True
        and info.get('established') is False and not info.get('restore_pending')
        and info.get('local_recovery_acknowledgement') is None
        and (recovery is None or isinstance(recovery, dict) and type(recovery.get('restore_generation')) is int
            and recovery['restore_generation'] == 0 and recovery.get('recovery_epoch_id') is None))
    return {'cache_stage': info['installer_cache_stage'], 'project': info['project'],
        'owner_token': info['owner_token'], 'initial_preparation': int(initial)}


def compare_journal_closure(info: dict, closure: Closure) -> None:
    pin = committed_pin(info)
    expected = {'schema_version': 1, 'profile': PROFILE, 'closure_sha256': closure.hash,
        **{key: closure.release[key] for key in ('launcher_sha256', 'bundle_sha256', 'verifier_reference', 'signer', 'issuer')}}
    if (pin != expected or info.get('image') != closure.release['runtime_reference']
            or any(info.get('image_admission', {}).get(key) != closure.release[key]
                for key in ('source_revision', 'source_snapshot', 'version'))):
        raise ValueError('fresh original closure contradicts the restored/selected immutable installed journal pin')
    closure.assert_unchanged()


def current_receipt(info: dict) -> dict:
    raw = _bounded_file(CURRENT_RECEIPT, 1024 * 1024, private=True)
    record = json.loads(raw, object_pairs_hook=pairs)
    pin = validate_receipt(record, admitted=info['image_admission'], reference=info['image'],
        journal_pin=committed_pin(info))
    validate_live_cache(info)
    if raw != _bounded_file(CURRENT_RECEIPT, 1024 * 1024, private=True):
        raise ValueError('fresh independent verifier receipt changed during the lifecycle check')
    return pin


def cache_name(canonical_state: str) -> str:
    state = Path(canonical_state)
    if (not state.is_absolute() or str(state) != canonical_state or '..' in state.parts
            or len(canonical_state) > 4096 or any(char in canonical_state for char in ('\r', '\n', '\x00', ',', ':'))
            or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._ $-]{0,127}', state.name) is None):
        raise ValueError('cache destination requires the exact canonical selected instance path')
    return state.name + '.installer-artifacts'


def validate_stage(canonical_state: str, basename: str) -> str:
    cache_name(canonical_state)  # validate the canonical fixed instance
    expected = '.originals.partial.'
    if (not isinstance(basename, str) or not basename.startswith(expected)
            or re.fullmatch(r'[A-Za-z0-9]{8}', basename[len(expected):]) is None):
        raise ValueError('cache staging name is not the selected instance fixed private publication intent')
    return basename


def anchor_inventory(descriptor: int, stage_basename: str) -> set[str]:
    """The ROI contains only THIS instance's verification children, never keys."""
    from uvm.installer.offline_artifacts import _directory
    _directory(descriptor)
    names = set()
    with os.scandir(descriptor) as entries:
        for entry in entries:
            if entry.name not in ('originals', stage_basename) or entry.name in names or len(names) >= 2:
                raise ValueError('dedicated cache anchor contains unknown or contradictory children')
            info = entry.stat(follow_symlinks=False)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError('cache anchor child is linked, foreign or not private')
            names.add(entry.name)
    return names


def durable_stage(canonical_state: str, stage_basename: str) -> None:
    """Persist the exact sibling entry before any initial identity/key mutation."""
    from uvm.installer.offline_artifacts import ROOT, _directory
    validate_stage(canonical_state, stage_basename)
    descriptor = os.open(CACHE_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if anchor_inventory(descriptor, stage_basename) != {stage_basename}:
            raise ValueError('new initialization requires ONLY its live original stage; a cache cannot recreate identity')
        staged = os.stat(stage_basename, dir_fd=descriptor, follow_symlinks=False)
        mounted = ROOT.lstat()
        if (staged.st_dev, staged.st_ino) != (mounted.st_dev, mounted.st_ino):
            raise ValueError('durable cache staging intent differs from the fresh fixed mount')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_live_cache(info: dict) -> str:
    """After journal/crypto comparison, observe ONLY its named stage/originals."""
    from uvm.installer.offline_artifacts import ROOT
    pin = committed_pin(info)
    stage_name = info['installer_cache_stage']
    descriptor = os.open(CACHE_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        names = anchor_inventory(descriptor, stage_name)
        mounted = ROOT.lstat()
        matched = None
        for name in ('originals', stage_name):
            if name in names:
                child = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (child.st_dev, child.st_ino) == (mounted.st_dev, mounted.st_ino): matched = name; break
        if matched is None:
            raise ValueError('bound cache view has no live original named entry in its dedicated anchor')
        if matched == stage_name and (info.get('initialized') is not True or info.get('installer_phase') != 'prepared'
                or info.get('established') is not False or info.get('restore_pending')
                or info.get('local_recovery_acknowledgement') is not None):
            raise ValueError('original stage is not an admissible interrupted initial publication intent')
        recovery = info.get('local_recovery_custody')
        if matched == stage_name and recovery is not None and (not isinstance(recovery, dict)
                or type(recovery.get('restore_generation')) is not int
                or recovery['restore_generation'] != 0 or recovery.get('recovery_epoch_id') is not None):
            raise ValueError('retained initial stage cannot resume a restored custody generation')
        current = Closure(fixture=None)
        if current.hash != pin['closure_sha256']:
            raise ValueError('live named cache contradicts committed original bytes')
        for name in names:
            other = Closure(fixture=None, custody_root=CACHE_PARENT / name)
            if other.hash != current.hash or other.files != current.files:
                raise ValueError('dedicated cache anchor contains conflicting verification children')
            other.assert_unchanged()
        current.assert_unchanged()
        return 'committed_originals' if matched == 'originals' else 'retained_initial_stage'
    finally:
        os.close(descriptor)


def publish_cache(canonical_state: str, stage_basename: str, pin: dict, observation: dict) -> dict:
    """Publish only already freshly authenticated bytes; no installation writer."""
    from uvm.installer.offline_artifacts import ROOT, _directory
    from uvm.installer.offline_lifecycle import _rename_new
    validate_pin(pin)
    cache_name(canonical_state)
    destination = 'originals'
    validate_stage(canonical_state, stage_basename)
    reject_mount_overlap(str(Path(canonical_state).parent / cache_name(canonical_state)), observation)
    parent = CACHE_PARENT
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _directory(descriptor)
        names = anchor_inventory(descriptor, stage_basename)
        before = os.fstat(descriptor)
        stage = parent / stage_basename
        current = Closure(fixture=None)
        if current.hash != pin['closure_sha256']:
            raise ValueError('freshly authenticated staging inventory changed before publication')
        current.assert_unchanged()
        fixed = ROOT.lstat()
        if stage_basename not in names:
            if 'originals' not in names:
                raise ValueError('both original stage and exact committed verification destination are missing')
            committed = (parent / 'originals').lstat()
            if (committed.st_dev, committed.st_ino) != (fixed.st_dev, fixed.st_ino):
                raise ValueError('missing original stage cannot be replaced by another bound view')
            exact = Closure(fixture=None, custody_root=parent / 'originals')
            if exact.hash != current.hash or exact.files != current.files:
                raise ValueError('committed verification destination contradicts the durable pin')
            exact.assert_unchanged()
            return {'cache_name': destination, 'closure_sha256': pin['closure_sha256'], 'publication': 'already_committed_exact_originals'}
        info = stage.lstat()
        if (info.st_dev, info.st_ino) != (fixed.st_dev, fixed.st_ino):
            raise ValueError('cache staging intent differs from the freshly verified original-closure mount')
        try:
            _rename_new(parent, stage_basename, destination)
            status = 'published_new'
        except OSError as exc:
            if exc.errno not in (errno.EEXIST, errno.ENOTEMPTY): raise
            # A concurrent winner is usable ONLY when every original byte is
            # identical to THIS freshly authenticated closure. Never overwrite,
            # remove, repair, or learn authority from the existing directory.
            existing = Closure(fixture=None, custody_root=parent / destination)
            if (existing.hash != current.hash or existing.files != current.files
                    or canonical(existing.document) != canonical(current.document)):
                raise ValueError('existing cache contradicts freshly authenticated original bytes')
            existing.assert_unchanged(); current.assert_unchanged()
            status = 'reused_exact_original_bytes'
        after = parent.lstat()
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError('cache parent changed during anchored publication')
        return {'cache_name': destination, 'closure_sha256': pin['closure_sha256'], 'publication': status}
    finally:
        os.close(descriptor)


def reject_mount_overlap(cache_path: str, observation: dict) -> None:
    if not isinstance(observation, dict) or set(observation) != {'containers', 'volumes'}:
        raise ValueError('closed actual API mount/volume observations required for cache custody')
    if not isinstance(observation['containers'], list) or not isinstance(observation['volumes'], list):
        raise ValueError('actual API mount/volume observations are malformed')
    cache = Path(cache_path)
    volumes = {}
    for volume in observation['volumes']:
        if (not isinstance(volume, dict) or not isinstance(volume.get('Name'), str)
                or volume['Name'] in volumes or volume.get('Driver') != 'local'
                or volume.get('Options') not in (None, {}) or not isinstance(volume.get('Mountpoint'), str)):
            raise ValueError('cache custody rejects ambiguous or bind-backed volume sources')
        volumes[volume['Name']] = volume['Mountpoint']
    for container in observation['containers']:
        if not isinstance(container, dict) or not isinstance(container.get('Mounts'), list):
            raise ValueError('actual API mount inventory is missing')
        for mount in container['Mounts']:
            if not isinstance(mount, dict): raise ValueError('actual API mount is malformed')
            if mount.get('Type') == 'bind': source = mount.get('Source')
            elif mount.get('Type') == 'volume': source = volumes.get(mount.get('Name'))
            else: continue
            if not isinstance(source, str) or not Path(source).is_absolute():
                raise ValueError('actual API mount source cannot be established')
            source = Path(source)
            if cache == source or cache in source.parents or source in cache.parents:
                raise ValueError('installed verification cache overlaps an actual API mount source or ancestor')
