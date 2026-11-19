"""Three fixed offline writers, executed only by the actual lifecycle FD owner."""
from __future__ import annotations

import ctypes
import argparse
import copy
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import signal
import time
import types
import uuid

from uvm.installer.lock import _bounded_file
from uvm.installer.offline_artifacts import canonical, digest, pairs
from uvm.installer.offline_backup import archive_inventory

ROOT = Path('/state')
INPUT = Path('/run/volt-offline-input')
OUTPUT = Path('/run/volt-offline-output')
SETUP = Path('/package/setup.py')
BACKUP_PARENT = Path('/run/volt-backup-publication')
BACKUP_VIEW = Path('/backup')
OBSERVATION = Path('/run/volt-offline-observation')
PROFILE = 'volt_offline_lifecycle_v1'
OPERATIONS = ('backup-record', 'restore-provision', 'restore-admit')
STORES = ('postgres', 'media', 'state')
MAX_INPUT = 8 * 1024 * 1024
MAX_WAIT = 900
FILE_IDENTITY = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
SHUTDOWN_MARKERS = ('G7_STOP_PHASE=writers status=0', 'G7_STOP_PHASE=workers status=0',
    'G7_STOP_DATABASE_STOPPED service=postgresql', 'G7_STOP_PHASE=databases status=0',
    'G7_SHUTDOWN=controlled service_cleanup_status=0')


def _started_at(value: str) -> str:
    if (not isinstance(value, str) or len(value) > 40
            or re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z', value) is None
            or datetime.fromisoformat(value).year < 1970):
        raise ValueError('actual queried container StartedAt is malformed')
    return value


def shutdown_evidence(stream, started_at: str) -> dict:
    """Stream the fixed Docker log tail with bounded memory, even for huge lines."""
    _started_at(started_at)
    needles = tuple(marker.encode() for marker in (*SHUTDOWN_MARKERS, 'G7_STOP_ERROR'))
    keep = max(map(len, needles)) - 1
    found, tail, count = set(), b'', 0
    while True:
        block = stream.read(65536)
        if not block:
            break
        count += len(block)
        combined = tail + block
        found.update(needle for needle in needles if needle in combined)
        tail = combined[-keep:]
    return {'schema_version': 1, 'profile': 'volt_controlled_stop_evidence_v1',
        'queried_started_at': started_at, 'markers': [marker for marker in SHUTDOWN_MARKERS if marker.encode() in found],
        'stop_error': b'G7_STOP_ERROR' in found, 'bytes_seen': count}


def read_shutdown_evidence(path: Path, actual_started_at: str) -> dict:
    raw = _bounded_file(path, 65536, private=True)
    value = json.loads(raw, object_pairs_hook=pairs)
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'profile', 'queried_started_at', 'markers', 'stop_error', 'bytes_seen'}
            or canonical(value) != raw or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['profile'] != 'volt_controlled_stop_evidence_v1'
            or value['queried_started_at'] != _started_at(actual_started_at)
            or value['markers'] != list(SHUTDOWN_MARKERS) or value['stop_error'] is not False
            or type(value['bytes_seen']) is not int or value['bytes_seen'] < 0):
        raise ValueError('bounded current-run shutdown evidence is incomplete, failed or bound to another StartedAt')
    return value


def owned_fd(fd: int) -> None:
    before = os.fstat(fd)
    current = (ROOT / '.install.lock').lstat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size')
    if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.getuid() or before.st_nlink != 1 or before.st_size != 0
            or any(getattr(before, key) != getattr(current, key) for key in fields)):
        raise ValueError('offline writer does not hold the current private lifecycle inode')
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if any(getattr(before, key) != getattr((ROOT / '.install.lock').lstat(), key) for key in fields):
        raise ValueError('offline lifecycle inode changed during ownership check')


def _directory(path: Path) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('offline private directory custody differs')


def _publish(directory: Path, name: str, value: dict) -> bytes:
    _directory(directory)
    destination = directory / name
    if destination.exists() or destination.is_symlink():
        raise ValueError('offline phase destination already exists')
    raw = canonical(value)
    temporary = directory / ('.phase.' + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        if os.geteuid() == 0:
            os.fchown(stream.fileno(), os.getuid(), -1)
    os.replace(temporary, destination)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return raw


def _identity(info: dict) -> dict:
    admitted, custody = info['image_admission'], info['local_recovery_custody']
    return {'installation_id': info['installation_id'], 'journal_id': info['local_recovery_journal_id'],
        'image_reference': info['image'], 'image_id': admitted['id'],
        'image_id_kind': admitted.get('id_kind', 'config'), 'source_revision': admitted['source_revision'],
        'source_snapshot': admitted['source_snapshot'], 'platform': info['platform'],
        'restore_generation': custody['restore_generation'], 'recovery_epoch_id': custody['recovery_epoch_id']}


class Exchange:
    def __init__(self, fd: int, operation: str):
        if operation not in OPERATIONS:
            raise ValueError('offline process action is not fixed')
        owned_fd(fd)
        _directory(INPUT); _directory(OUTPUT)
        if any(OUTPUT.iterdir()) or {path.name for path in INPUT.iterdir()} != {'request.json'}:
            raise ValueError('offline exchange output is not fresh')
        request = json.loads(_bounded_file(INPUT / 'request.json', 65536, private=True), object_pairs_hook=pairs)
        if (not isinstance(request, dict) or set(request) != {'schema_version', 'profile', 'setup_sha256', 'backup_name'}
                or type(request['schema_version']) is not int or request['schema_version'] != 1
                or request['profile'] != 'volt_offline_request_v1'
                or not isinstance(request['setup_sha256'], str)
                or re.fullmatch(r'sha256:[0-9a-f]{64}', request['setup_sha256']) is None):
            raise ValueError('offline fixed request is malformed')
        if operation == 'backup-record':
            if (not isinstance(request['backup_name'], str)
                    or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', request['backup_name']) is None):
                raise ValueError('offline backup destination is not a new bounded basename')
        elif request['backup_name'] is not None:
            raise ValueError('restore request cannot select a backup destination')
        code = _bounded_file(SETUP, 1024 * 1024, private=False)
        if digest(code) != request['setup_sha256']:
            raise ValueError('fixed admitted offline setup bytes changed')
        setup = types.ModuleType('_volt_fixed_offline_setup'); setup.__file__ = str(SETUP)
        exec(compile(code, str(SETUP), 'exec'), setup.__dict__)
        self.fd, self.operation, self.setup = fd, operation, setup
        self.lock_identity = tuple(getattr(os.fstat(fd), key) for key in
            ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
        self.operation_id, self.previous = str(uuid.uuid4()), None
        self.request = request
        self.inputs = {'request.json': tuple(getattr((INPUT / 'request.json').lstat(), key) for key in FILE_IDENTITY)}
        self.info = self._load()
        self.expected_journal = digest(_bounded_file(ROOT / 'instance.json', 1024 * 1024, private=True))

    def _load(self) -> dict:
        owned_fd(self.fd)
        before = _bounded_file(ROOT / 'instance.json', 1024 * 1024, private=True)
        _root, info = self.setup.load_instance(str(ROOT), allow_restore_transition=self.operation == 'restore-provision')
        if (before != _bounded_file(ROOT / 'instance.json', 1024 * 1024, private=True)
                or info != json.loads(before, object_pairs_hook=pairs) or info.get('mode') != 'local'):
            raise ValueError('offline instance journal changed or is not local')
        from uvm.installer.installed_artifacts import committed_pin
        committed_pin(info)
        if self.operation != 'restore-provision' or info.get('restore_fence_transition') is None:
            from uvm.installer.recovery_authority import _request_for_instance, _resume
            _resume(ROOT, _request_for_instance(ROOT))
        return info

    def unchanged(self) -> None:
        owned_fd(self.fd)
        _directory(INPUT); _directory(OUTPUT)
        for name, expected in self.inputs.items():
            if tuple(getattr((INPUT / name).lstat(), key) for key in FILE_IDENTITY) != expected:
                raise ValueError('offline request or acknowledged phase changed after consumption')
        if tuple(getattr(os.fstat(self.fd), key) for key in
                ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')) != self.lock_identity:
            raise ValueError('offline held lifecycle inode changed during operation')
        if digest(_bounded_file(ROOT / 'instance.json', 1024 * 1024, private=True)) != self.expected_journal:
            raise ValueError('offline journal changed outside this FD owner')
        self._load()

    def commit(self) -> None:
        from uvm.installer.recovery_authority import _commit_metadata
        self.unchanged()
        _commit_metadata(ROOT, self.info)
        owned_fd(self.fd)
        self.expected_journal = digest(_bounded_file(ROOT / 'instance.json', 1024 * 1024, private=True))

    def record(self, phase: str, data: dict) -> dict:
        return {'schema_version': 1, 'profile': PROFILE, 'operation': self.operation,
            'operation_id': self.operation_id, 'identity': _identity(self.info), 'phase': phase,
            'predecessor_sha256': self.previous, 'data': data}

    def emit(self, phase: str, data: dict) -> None:
        self.unchanged()
        self.previous = digest(_publish(OUTPUT, phase + '.json', self.record(phase, data)))
        print(json.dumps({'offline_phase': phase, 'operation_id': self.operation_id,
            'record_sha256': self.previous}, sort_keys=True), flush=True)

    def receive(self, phase: str) -> dict:
        deadline = time.monotonic() + MAX_WAIT
        while True:
            self.unchanged()
            try:
                raw = _bounded_file(INPUT / (phase + '.json'), MAX_INPUT, private=True)
                break
            except FileNotFoundError:
                if time.monotonic() >= deadline:
                    raise ValueError('offline host phase acknowledgement timed out') from None
                time.sleep(0.1)
        value = json.loads(raw, object_pairs_hook=pairs)
        expected = self.record(phase, {})
        if (not isinstance(value, dict) or set(value) != set(expected) or canonical(value) != raw
                or type(value['schema_version']) is not int
                or not isinstance(value['identity'], dict)
                or type(value['identity'].get('restore_generation')) is not int
                or any(value[key] != expected[key] for key in expected if key != 'data')
                or not isinstance(value['data'], dict)):
            raise ValueError('offline exchange phase/UUID/identity/predecessor differs')
        self.previous = digest(raw)
        name = phase + '.json'
        self.inputs[name] = tuple(getattr((INPUT / name).lstat(), key) for key in FILE_IDENTITY)
        if {path.name for path in INPUT.iterdir()} != set(self.inputs):
            raise ValueError('offline input inventory contains stale or unexpected phase data')
        return value['data']


def resource_plan(info: dict) -> dict:
    return {'project': info['project'], 'owner_token': info['owner_token'], 'image': info['image'],
        'platform': info['platform'], 'subnet': info['subnet'], 'gateway': info['gateway'],
        'network_internal': False, 'volumes': [info['project'] + '_' + store for store in STORES],
        'network': info['project'] + '_network', 'container': info['project'] + '-volt-1'}


def validate_observation(info: dict, data: dict, *, container: bool, complete: bool) -> None:
    if set(data) != {'image', 'containers', 'volumes', 'networks', 'logs', 'logs_since', 'inventories', 'independent_admission'}:
        raise ValueError('closed offline Docker observation required')
    from uvm.installer.installed_artifacts import committed_pin, validate_receipt, validate_live_cache
    validate_receipt(data['independent_admission'], admitted=info['image_admission'], reference=info['image'],
        journal_pin=committed_pin(info))
    validate_live_cache(info)
    image = data['image']; admitted = info['image_admission']
    if (not isinstance(image, dict) or set(image) != {'Id', 'Os', 'Architecture', 'Descriptor', 'Labels'}
            or image['Id'] != admitted['id'] or image['Os'] + '/' + image['Architecture'] != info['platform']
            or image['Labels'].get('org.opencontainers.image.revision') != admitted['source_revision']
            or image['Labels'].get('org.volt.compose.source-snapshot') != admitted['source_snapshot']
            or image['Labels'].get('org.opencontainers.image.version') != admitted['version']):
        raise ValueError('offline helper image differs from admitted native identity/source')
    if admitted.get('id_kind') == 'selected_manifest' and any(image['Descriptor'].get(key) !=
            admitted['selected_descriptor'].get(key) for key in ('digest', 'size', 'mediaType', 'platform')):
        raise ValueError('offline helper selected-child descriptor differs')
    if not all(isinstance(data[key], list) for key in ('containers', 'volumes', 'networks')):
        raise ValueError('offline resource inspection arrays required')
    if len(data['containers']) != int(container) or len(data['networks']) > 1 or len(data['volumes']) > 3:
        raise ValueError('offline runtime/resource presence differs')
    wanted = set(resource_plan(info)['volumes']); names = set()
    for volume in data['volumes']:
        if (not isinstance(volume, dict) or set(volume) != {'Name', 'Driver', 'Scope', 'Mountpoint', 'Options', 'Labels'}
                or volume['Name'] not in wanted or volume['Name'] in names or volume['Driver'] != 'local'
                or volume['Scope'] != 'local' or volume['Options'] not in (None, {})
                or volume['Labels'].get('volt.compose.owner-token') != info['owner_token']):
            raise ValueError('offline volume name/driver/ownership differs')
        names.add(volume['Name'])
    if complete and names != wanted:
        raise ValueError('offline owned store set is incomplete')
    if complete and len(data['networks']) != 1:
        raise ValueError('offline owned application network is missing')
    for network in data['networks']:
        if (not isinstance(network, dict) or set(network) != {'Name', 'Id', 'Driver', 'Internal', 'Labels', 'IPAM', 'Containers'}
                or network['Name'] != info['project'] + '_network' or network['Driver'] != 'bridge'
                or network['Internal'] is not False or not isinstance(network['Containers'], dict) or network['Containers']
                or re.fullmatch(r'[0-9a-f]{64}', network['Id']) is None
                or network['Labels'].get('volt.compose.owner-token') != info['owner_token']
                or network['IPAM'] != {'Config': [{'Subnet': info['subnet'], 'Gateway': info['gateway']}]}):
            raise ValueError('offline network topology/ownership differs or has attached workers')
    if container:
        from uvm.installer.runtime_mounts import validate
        item = data['containers'][0]
        if (not isinstance(item, dict) or set(item) != {'Name', 'Id', 'Image', 'ImageManifestDescriptor',
                    'Config', 'HostConfig', 'NetworkSettings', 'Mounts', 'State'}
                or item.get('Name') != '/' + info['project'] + '-volt-1'
                or re.fullmatch(r'[0-9a-f]{64}', item['Id']) is None
                or set(item['Config']) != {'Labels'} or set(item['HostConfig']) != {'NetworkMode'}
                or set(item['NetworkSettings']) != {'Networks'}
                or set(item['State']) != {'Running', 'Paused', 'Restarting', 'OOMKilled', 'ExitCode', 'Error', 'StartedAt'}
                or any(set(mount) != {'Type', 'Name', 'Source', 'Destination', 'Driver', 'RW'} for mount in item['Mounts'])):
            raise ValueError('offline stopped container identity differs')
        validate(ROOT, Path(info['host_instance_directory']), info, item, data['volumes'])
        state = item['State']
        if (any(state.get(key) is not False for key in ('Running', 'Paused', 'Restarting', 'OOMKilled'))
                or type(state.get('ExitCode')) is not int or state.get('ExitCode') != 0 or state.get('Error') or not state.get('StartedAt')
                or state['StartedAt'].startswith('0001-') or data['logs_since'] != state['StartedAt']):
            raise ValueError('offline backup requires current successful controlled stop')
        if not isinstance(data['logs'], str) or any(marker not in data['logs'] for marker in SHUTDOWN_MARKERS) or 'G7_STOP_ERROR' in data['logs']:
            raise ValueError('current controlled shutdown markers are missing or failed')
    elif data['logs'] != '' or data['logs_since'] is not None:
        raise ValueError('restore observation must not carry runtime logs')


def inventories(value: dict, stores: tuple[str, ...]) -> dict:
    if not isinstance(value, dict) or set(value) != set(stores):
        raise ValueError('offline inventory store set differs')
    for store, item in value.items():
        if (not isinstance(item, dict) or set(item) != {'sha256', 'entries', 'postgres_version'}
                or not isinstance(item['sha256'], str) or re.fullmatch(r'[0-9a-f]{64}', item['sha256']) is None
                or type(item['entries']) is not int or not 0 <= item['entries'] < 250000
                or (store == 'postgres' and (not isinstance(item['postgres_version'], str)
                    or re.fullmatch(r'[0-9]{1,2}(?:\.[0-9]{1,2})?', item['postgres_version']) is None))
                or (store != 'postgres' and item['postgres_version'] is not None)):
            raise ValueError('offline store inventory is malformed')
    if 'postgres' in stores and not value['postgres']['postgres_version']:
        raise ValueError('offline PostgreSQL inventory lacks PG_VERSION')
    return value


def canonical_resources(data: dict) -> dict:
    """Normalize only named sets; retain EVERY row value and reject duplicates."""
    result = copy.deepcopy({key: data[key] for key in ('image', 'containers', 'volumes', 'networks')})

    def ordered(rows, key):
        if not isinstance(rows, list) or any(not isinstance(row, dict) or not isinstance(row.get(key), str) for row in rows):
            raise ValueError('offline resource set lacks typed unique identity')
        names = [row[key] for row in rows]
        if len(set(names)) != len(names):
            raise ValueError('offline resource set contains duplicate identity: ' + key)
        return sorted(rows, key=lambda row: row[key])

    result['containers'] = ordered(result['containers'], 'Id')
    for item in result['containers']:
        item['Mounts'] = ordered(item['Mounts'], 'Destination')
    result['volumes'] = ordered(result['volumes'], 'Name')
    result['networks'] = ordered(result['networks'], 'Name')
    return result


def redacted_projection(value):
    if isinstance(value, dict):
        return {key: redacted_projection(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redacted_projection(item) for item in value]
    return {'type': type(value).__name__, 'value_sha256': digest(canonical({'value': value}))}


def trace_resources(exchange: Exchange, phase: str, data: dict) -> dict:
    projection = canonical_resources(data)
    print(json.dumps({'offline_resource_phase': phase, 'operation_id': exchange.operation_id,
        'projection_sha256': digest(canonical(projection)),
        'redacted_projection': redacted_projection(projection)}, sort_keys=True), flush=True)
    return projection


def _rename_new(parent: Path, source: str, destination: str) -> None:
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        rename = getattr(libc, 'renameat2', None)
        if rename is None:
            raise ValueError('atomic no-replace backup publication is unsupported')
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        if rename(descriptor, source.encode(), descriptor, destination.encode(), 1):
            raise OSError(ctypes.get_errno(), 'atomic new backup destination publication failed')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _complete_capture(exchange: Exchange, directory: Path, name: str, archives: dict) -> None:
    completion = exchange.record('complete', {'backup_name': name, 'archives': archives})
    completion_raw = _publish(directory, 'completion.json', completion)
    exchange.unchanged()
    _rename_new(BACKUP_PARENT, directory.name, name)
    # Publication commits the validated capture. Subsequent owner/response loss
    # cannot retract it. Exact read-only reconciliation never infers host receipt.
    print(json.dumps({'offline_publication_committed': name, 'operation_id': exchange.operation_id,
        'identity_sha256': digest(canonical(completion['identity'])),
        'completion_sha256': digest(completion_raw)}, sort_keys=True), flush=True)
    owned_fd(exchange.fd)
    exchange.emit('complete', {'backup_name': name, 'archives': archives})


def execute(fd: int, operation: str) -> None:
    exchange = Exchange(fd, operation)
    exchange.emit('plan', resource_plan(exchange.info))
    observed = exchange.receive('observed')
    validate_observation(exchange.info, observed, container=operation == 'backup-record', complete=operation != 'restore-provision')
    if operation == 'backup-record':
        if not exchange.info.get('established') or exchange.info.get('restore_pending'):
            raise ValueError('offline capture requires established non-pending state')
        _directory(BACKUP_PARENT)
        name = exchange.request['backup_name']
        if (BACKUP_PARENT / name).exists() or (BACKUP_PARENT / name).is_symlink():
            raise ValueError('backup destination already exists; reconcile it read-only with its original operation ID and identity hash')
        captured = inventories(observed['inventories'], STORES)
        before_resources = trace_resources(exchange, 'observed', observed)
        exchange.info['backup_inventory'] = captured
        exchange.commit()
        partial = '.' + name + '.partial.' + exchange.operation_id
        (BACKUP_PARENT / partial).mkdir(mode=0o700)
        if os.geteuid() == 0:
            os.chown(BACKUP_PARENT / partial, os.getuid(), -1)
        exchange.emit('capture', {'partial_name': partial, 'archive_names': [store + '.tar' for store in (*STORES, 'instance')]})
        final = exchange.receive('captured')
        validate_observation(exchange.info, final, container=True, complete=True)
        actual = inventories(final['inventories'], (*STORES, 'instance'))
        after_resources = trace_resources(exchange, 'captured', final)
        if any(actual[store] != captured[store] for store in STORES):
            raise ValueError('offline stores changed during archive capture')
        if before_resources != after_resources:
            raise ValueError('offline actual resource identities changed during capture')
        directory = BACKUP_PARENT / partial
        if {path.name for path in directory.iterdir()} != {store + '.tar' for store in (*STORES, 'instance')}:
            raise ValueError('private capture archive inventory differs')
        archives = {}
        for store in (*STORES, 'instance'):
            exchange.unchanged()
            path = directory / (store + '.tar'); info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 64 * 1024**3):
                raise ValueError('private captured archive custody differs')
            if archive_inventory(path) != actual[store]:
                raise ValueError('captured archive content differs from final read-only source inventory')
            checksum = hashlib.sha256()
            descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(descriptor, 'rb') as stream:
                if any(getattr(os.fstat(stream.fileno()), key) != getattr(info, key) for key in FILE_IDENTITY):
                    raise ValueError('captured archive changed after content validation')
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    checksum.update(block)
                if any(getattr(info, key) != getattr(after, key)
                        for after in (os.fstat(stream.fileno()), path.lstat()) for key in FILE_IDENTITY):
                    raise ValueError('captured archive changed during final digest acknowledgement')
                os.fsync(stream.fileno())
            archives[path.name] = {'bytes': info.st_size, 'sha256': 'sha256:' + checksum.hexdigest()}
        _complete_capture(exchange, directory, name, archives)
    elif operation == 'restore-provision':
        if not exchange.info.get('restore_pending') and (observed['volumes'] or observed['networks']):
            raise ValueError('fresh restore cannot adopt existing resources')
        inventories(exchange.info.get('backup_inventory'), STORES)
        if exchange.info.get('restore_imported'):
            raise ValueError('restore cannot provision after import admission')
        from uvm.installer.recovery_authority import advance_fence
        if not exchange.info.get('restore_pending') or exchange.info.get('restore_fence_transition') is not None:
            exchange.unchanged()
            advance_fence(types.SimpleNamespace(instance_root=str(ROOT)))
            owned_fd(fd)
            exchange.info = exchange._load()
            exchange.expected_journal = digest(_bounded_file(ROOT / 'instance.json', 1024 * 1024, private=True))
        exchange.emit('provision', resource_plan(exchange.info))
        final = exchange.receive('provisioned')
        validate_observation(exchange.info, final, container=False, complete=True)
        exchange.emit('complete', {'restore_pending': True, 'restore_imported': False})
    else:
        if not exchange.info.get('restore_pending') or exchange.info.get('restore_imported'):
            raise ValueError('offline restore is not awaiting store admission')
        actual = inventories(observed['inventories'], STORES)
        if actual != exchange.info.get('backup_inventory'):
            raise ValueError('offline imports differ from captured store inventories')
        exchange.info['restore_imported'] = True
        exchange.commit()
        exchange.emit('complete', {'restore_pending': True, 'restore_imported': True})


def backup_status(operation_id: str, identity_sha256: str, backup_name: str) -> dict:
    """Reconcile one published capture read-only; never grant restore authority."""
    if (not isinstance(operation_id, str) or str(uuid.UUID(operation_id)) != operation_id
            or uuid.UUID(operation_id).version != 4 or not isinstance(identity_sha256, str)
            or re.fullmatch(r'sha256:[0-9a-f]{64}', identity_sha256) is None
            or not isinstance(backup_name, str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', backup_name) is None):
        raise ValueError('exact original operation ID, identity hash and published backup basename are required')
    directory = BACKUP_VIEW
    _directory(directory)
    names = {store + '.tar' for store in (*STORES, 'instance')}
    if {path.name for path in directory.iterdir()} != names | {'completion.json'}:
        raise ValueError('backup is not a complete published archive inventory')
    raw = _bounded_file(directory / 'completion.json', 65536, private=True)
    value = json.loads(raw, object_pairs_hook=pairs)
    fields = {'schema_version', 'profile', 'operation', 'operation_id', 'identity', 'phase', 'predecessor_sha256', 'data'}
    if (not isinstance(value, dict) or set(value) != fields or canonical(value) != raw
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['profile'] != PROFILE or value['operation'] != 'backup-record' or value['phase'] != 'complete'
            or value['operation_id'] != operation_id or digest(canonical(value['identity'])) != identity_sha256
            or not isinstance(value['predecessor_sha256'], str)
            or re.fullmatch(r'sha256:[0-9a-f]{64}', value['predecessor_sha256']) is None
            or not isinstance(value['data'], dict) or set(value['data']) != {'backup_name', 'archives'}
            or value['data']['backup_name'] != backup_name or not isinstance(value['data']['archives'], dict)
            or set(value['data']['archives']) != names):
        raise ValueError('completed capture receipt does not match the exact original operation/identity/destination')
    metadata_raw = _bounded_file(ROOT / 'instance.json', 1024 * 1024, private=True)
    metadata = json.loads(metadata_raw, object_pairs_hook=pairs)
    current = _identity(metadata)
    identity_fields = set(current)
    if (not isinstance(value['identity'], dict) or set(value['identity']) != identity_fields
            or type(value['identity']['restore_generation']) is not int
            or value['identity']['restore_generation'] < 0
            or any(value['identity'][key] != current[key] for key in identity_fields - {'restore_generation', 'recovery_epoch_id'})):
        raise ValueError('published capture belongs to another installation/journal/image/source')
    generation = value['identity']['restore_generation']
    epoch = value['identity']['recovery_epoch_id']
    if ((generation == 0 and epoch is not None) or (generation > 0 and (
            not isinstance(epoch, str) or str(uuid.UUID(epoch)) != epoch or uuid.UUID(epoch).version != 4))):
        raise ValueError('published capture restore tuple is malformed')
    for name, expected in value['data']['archives'].items():
        path = directory / name
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not isinstance(expected, dict) or set(expected) != {'bytes', 'sha256'}
                    or type(expected['bytes']) is not int or not 0 <= expected['bytes'] <= 64 * 1024**3
                    or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != expected['bytes']):
                raise ValueError('published archive custody/size differs')
            checksum = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                checksum.update(block)
            if ('sha256:' + checksum.hexdigest() != expected['sha256'] or any(
                    getattr(info, key) != getattr(after, key)
                    for after in (os.fstat(stream.fileno()), path.lstat()) for key in FILE_IDENTITY)):
                raise ValueError('published archive digest/identity changed')
    if raw != _bounded_file(directory / 'completion.json', 65536, private=True):
        raise ValueError('published completion receipt changed during readback')
    if metadata_raw != _bounded_file(ROOT / 'instance.json', 1024 * 1024, private=True):
        raise ValueError('selected instance changed during completed capture readback; retry read-only')
    return {'status': 'completed_capture', 'operation_id': operation_id, 'identity_sha256': identity_sha256,
        'completion_sha256': digest(raw), 'backup_name': backup_name, 'read_only_reconciliation': True,
        'host_response_acknowledgement': 'not_inferred', 'restore_authority': False,
        'archives': value['data']['archives']}


def _response(phase: str) -> tuple[dict, bytes]:
    if phase not in ('plan', 'capture', 'provision', 'complete'):
        raise ValueError('unknown fixed offline response phase')
    raw = _bounded_file(OUTPUT / (phase + '.json'), 65536, private=True)
    value = json.loads(raw, object_pairs_hook=pairs)
    fields = {'schema_version', 'profile', 'operation', 'operation_id', 'identity', 'phase', 'predecessor_sha256', 'data'}
    identity_fields = {'installation_id', 'journal_id', 'image_reference', 'image_id', 'image_id_kind',
        'source_revision', 'source_snapshot', 'platform', 'restore_generation', 'recovery_epoch_id'}
    if (not isinstance(value, dict) or set(value) != fields or canonical(value) != raw
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['profile'] != PROFILE or value['operation'] not in OPERATIONS
            or value['phase'] != phase or not isinstance(value['identity'], dict)
            or set(value['identity']) != identity_fields or not isinstance(value['data'], dict)
            or str(uuid.UUID(value['operation_id'])) != value['operation_id'] or uuid.UUID(value['operation_id']).version != 4
            or type(value['identity']['restore_generation']) is not int):
        raise ValueError('closed current offline owner response required')
    return value, raw


def project_observation(value: dict) -> dict:
    """Project bounded Docker CLI data into the fixed writer input schema."""
    if (not isinstance(value, dict) or set(value) != {'image', 'containers', 'volumes', 'networks'}
            or any(not isinstance(value[key], list) for key in value) or len(value['image']) != 1
            or len(value['containers']) > 1 or len(value['volumes']) > 3 or len(value['networks']) > 1):
        raise ValueError('closed Docker observation arrays required')
    image = value['image'][0]
    projected = {'image': {key: image.get(key) for key in ('Id', 'Os', 'Architecture', 'Descriptor')},
        'containers': [], 'volumes': [], 'networks': []}
    projected['image']['Labels'] = image.get('Config', {}).get('Labels') or {}
    for item in value['containers']:
        row = {key: item.get(key) for key in ('Name', 'Id', 'Image', 'ImageManifestDescriptor')}
        row.update(Config={'Labels': item.get('Config', {}).get('Labels') or {}},
            HostConfig={'NetworkMode': item['HostConfig']['NetworkMode']},
            NetworkSettings={'Networks': {name: {key: data.get(key) for key in ('NetworkID', 'DriverOpts')}
                for name, data in item['NetworkSettings']['Networks'].items()}},
            Mounts=[{key: mount.get(key) for key in ('Type', 'Name', 'Source', 'Destination', 'Driver', 'RW')}
                    for mount in item['Mounts']],
            State={key: item['State'].get(key) for key in ('Running', 'Paused', 'Restarting', 'OOMKilled', 'ExitCode', 'Error', 'StartedAt')})
        projected['containers'].append(row)
    for item in value['volumes']:
        projected['volumes'].append({key: item.get(key) for key in ('Name', 'Driver', 'Scope', 'Mountpoint', 'Options', 'Labels')})
    for item in value['networks']:
        row = {key: item.get(key) for key in ('Name', 'Id', 'Driver', 'Internal', 'Labels', 'Containers')}
        row['IPAM'] = {'Config': item['IPAM']['Config']}
        projected['networks'].append(row)
    return projected


def emit_observation(phase: str) -> None:
    previous_phase = {'observed': 'plan', 'captured': 'capture', 'provisioned': 'provision'}.get(phase)
    if previous_phase is None:
        raise ValueError('unknown fixed offline observation phase')
    previous, raw = _response(previous_phase)
    _directory(OBSERVATION)
    observed = json.loads(_bounded_file(OBSERVATION / 'docker.json', MAX_INPUT, private=True), object_pairs_hook=pairs)
    data = project_observation(observed)
    if data['containers']:
        proof = read_shutdown_evidence(OBSERVATION / 'shutdown-evidence.json', data['containers'][0]['State']['StartedAt'])
        logs = '\n'.join(proof['markers'])
        since = proof['queried_started_at']
    else:
        logs, since = '', None
    inventory_file = OBSERVATION / 'inventories.json'
    data.update(logs=logs, logs_since=since,
        inventories=json.loads(_bounded_file(inventory_file, 65536, private=True), object_pairs_hook=pairs),
        independent_admission=json.loads(_bounded_file(OBSERVATION / 'independent-admission.json',
            1024 * 1024, private=True), object_pairs_hook=pairs))
    value = {**previous, 'phase': phase, 'predecessor_sha256': digest(raw), 'data': data}
    print(canonical(value).decode(), end='')


def plan_lines(phase: str) -> None:
    value, _raw = _response(phase)
    data = value['data']
    if phase in ('plan', 'provision'):
        keys = {'project', 'owner_token', 'image', 'platform', 'subnet', 'gateway',
            'network_internal', 'volumes', 'network', 'container'}
        if set(data) != keys or type(data['network_internal']) is not bool or len(data['volumes']) != 3:
            raise ValueError('closed offline resource plan required')
        if (re.fullmatch(r'[a-z][a-z0-9_-]{0,62}', data['project']) is None
                or re.fullmatch(r'[0-9a-f]{64}', data['owner_token']) is None
                or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9./:@_-]{1,1023}', data['image']) is None
                or data['platform'] not in ('linux/amd64', 'linux/arm64')
                or data['network'] != data['project'] + '_network'
                or data['container'] != data['project'] + '-volt-1'
                or data['volumes'] != [data['project'] + '_' + store for store in STORES]
                or data['network_internal'] is not False):
            raise ValueError('offline plan is outside the fixed ordinary instance resource namespace')
        lines = {key: data[key] for key in keys - {'volumes', 'network_internal'}}
        lines['network_internal'] = str(int(data['network_internal']))
        lines.update({'volume_' + name: data['volumes'][i] for i, name in enumerate(STORES)})
    elif phase == 'capture':
        if (set(data) != {'partial_name', 'archive_names'}
                or data['archive_names'] != [store + '.tar' for store in (*STORES, 'instance')]
                or re.fullmatch(r'\.[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.partial\.[0-9a-f-]{36}', data['partial_name']) is None):
            raise ValueError('closed private archive plan required')
        lines = {'partial_name': data['partial_name']}
    else:
        lines = {'phase': phase}
    lines.update(operation_id=value['operation_id'], identity_sha256=digest(canonical(value['identity'])))
    for key in sorted(lines):
        text = lines[key]
        if not isinstance(text, str) or not text or len(text) > 4096 or any(char in text for char in ('\n', '\r', '\x00')):
            raise ValueError('offline shell data is malformed')
        print(key + '=' + text)


def main() -> int:
    parser = argparse.ArgumentParser(description='Fixed data-only offline lifecycle adapters')
    parser.add_argument('action', choices=('emit-request', 'emit-observation', 'plan-lines', 'queried-started-at', 'filter-shutdown', 'backup-status'))
    parser.add_argument('--phase', choices=('plan', 'capture', 'provision', 'complete', 'observed', 'captured', 'provisioned'))
    parser.add_argument('--backup-name')
    parser.add_argument('--started-at')
    parser.add_argument('--operation-id')
    parser.add_argument('--identity-sha256')
    args = parser.parse_args()
    if args.action != 'backup-status' and (args.operation_id is not None or args.identity_sha256 is not None):
        parser.error('capture readback identity is not an execution capability')
    if args.action not in ('filter-shutdown', 'queried-started-at') and args.started_at is not None:
        parser.error('query StartedAt is not a lifecycle selector')
    if args.action == 'backup-status':
        if args.phase is not None or args.started_at is not None:
            parser.error('readback cannot select a phase or query')
        print(json.dumps(backup_status(args.operation_id, args.identity_sha256, args.backup_name), sort_keys=True))
    elif args.action == 'filter-shutdown':
        if args.phase is not None or args.backup_name is not None:
            parser.error('shutdown filtering has only its actual query StartedAt')
        def timed_out(_number, _frame):
            raise TimeoutError('bounded shutdown evidence acquisition timed out')
        old = signal.signal(signal.SIGALRM, timed_out)
        signal.alarm(120)
        try:
            value = shutdown_evidence(sys.stdin.buffer, args.started_at)
        finally:
            signal.alarm(0); signal.signal(signal.SIGALRM, old)
        print(canonical(value).decode(), end='')
        if value['markers'] != list(SHUTDOWN_MARKERS) or value['stop_error']:
            parser.error('current-run shutdown evidence is missing or failed')
    elif args.action == 'queried-started-at':
        if any(value is not None for value in (args.phase, args.backup_name, args.started_at)):
            parser.error('current StartedAt comes only from the saved Docker observation')
        raw = json.loads(_bounded_file(OBSERVATION / 'docker.json', MAX_INPUT, private=True), object_pairs_hook=pairs)
        if len(raw.get('containers', [])) != 1:
            parser.error('one actual stopped container is required for the log query')
        print(_started_at(raw['containers'][0]['State']['StartedAt']))
    elif args.action == 'emit-request':
        if args.phase is not None:
            parser.error('request emission has no phase selector')
        if args.backup_name is not None and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', args.backup_name) is None:
            parser.error('backup name is not a bounded new basename')
        code = _bounded_file(SETUP, 1024 * 1024, private=False)
        print(canonical({'schema_version': 1, 'profile': 'volt_offline_request_v1',
            'setup_sha256': digest(code), 'backup_name': args.backup_name}).decode(), end='')
    elif args.action == 'emit-observation':
        if args.backup_name is not None:
            parser.error('observation cannot select a destination')
        emit_observation(args.phase)
    else:
        if args.backup_name is not None:
            parser.error('plan decoding cannot select a destination')
        plan_lines(args.phase)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
