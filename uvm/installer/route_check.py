"""Delivery boundaries for the fixed private transient-routing protocol.

Runtime state types/custody belong to uvm.auth.route_check. This module never
accepts a public identity, arbitrary file path, Docker socket or signing key.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

PROFILE = 'volt_transient_route_check_v1'
MAX_RECORD = 8192
MAX_TAR = 128 * 1024
MAX_ENTRIES = 32
ERROR_CODES = frozenset({'invalid_input', 'custody_invalid', 'process_not_ready',
    'identity_mismatch', 'operation_conflict', 'operation_expired',
    'observation_missing', 'state_inconsistent', 'cleanup_failed'})
API_COMMAND = (b'/opt/uvm/venv/bin/python', b'-m', b'uvm.api.main_server')


class RouteCheckError(ValueError):
    def __init__(self, code: str):
        if code not in ERROR_CODES:
            code = 'state_inconsistent'
        self.code = code
        super().__init__('route_check_failed:' + code)


def require(condition, code='state_inconsistent'):
    if not condition:
        raise RouteCheckError(code)


def _proc_bytes(pid: int, name: str) -> bytes:
    require(type(pid) is int and 0 < pid <= 2147483647, 'process_not_ready')
    require(name in ('stat', 'status', 'cmdline'), 'invalid_input')
    try:
        descriptor = os.open(f'/proc/{pid}/{name}', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            data = os.read(descriptor, MAX_RECORD + 1)
            require(len(data) <= MAX_RECORD, 'process_not_ready')
            return data
        finally:
            os.close(descriptor)
    except OSError:
        raise RouteCheckError('process_not_ready') from None


def parse_proc_stat(raw: bytes, pid: int, *, cleanup_only=False) -> dict:
    """Linux comm can contain spaces and closing parentheses; field22 is ticks."""
    try:
        require(len(raw) <= MAX_RECORD and raw.startswith(str(pid).encode() + b' ('), 'process_not_ready')
        close = raw.rfind(b')')
        require(close > 0 and raw[close + 1:close + 2] == b' ', 'process_not_ready')
        fields = raw[close + 2:].split()
        require(len(fields) >= 20 and fields[0] in ((b'R',b'S',b'D',b'I',b'T',b't') if cleanup_only else (b'R',b'S',b'D',b'I')), 'process_not_ready')
        result = {'pid': pid, 'proc_start_ticks': int(fields[19]),
            'ppid': int(fields[1]), 'pgid': int(fields[2]), 'sid': int(fields[3])}
        require(0 < result['proc_start_ticks'] <= 2**63 - 1
            and all(0 <= result[k] <= 2147483647 for k in ('ppid', 'pgid', 'sid')), 'process_not_ready')
        return result
    except (ValueError, IndexError, TypeError):
        raise RouteCheckError('process_not_ready') from None


def _process_snapshot(pid: int, uid: int, gid: int) -> dict:
    before = parse_proc_stat(_proc_bytes(pid, 'stat'), pid)
    status = _proc_bytes(pid, 'status')
    for field, expected in ((b'Uid', uid), (b'Gid', gid)):
        rows = [line for line in status.splitlines() if line.startswith(field + b':')]
        require(len(rows) == 1, 'process_not_ready')
        try:
            values = [int(value) for value in rows[0].split(b':', 1)[1].split()]
        except ValueError:
            raise RouteCheckError('process_not_ready') from None
        require(values == [expected] * 4, 'process_not_ready')
    command_raw = _proc_bytes(pid, 'cmdline')
    require(command_raw.endswith(b'\0'), 'process_not_ready')
    command = tuple(command_raw[:-1].split(b'\0'))
    after = parse_proc_stat(_proc_bytes(pid, 'stat'), pid)
    require(before == after, 'process_not_ready')
    return {**after, 'command': command}



def _admitted_executable(pid: int) -> None:
    try:
        expected = os.stat('/opt/uvm/venv/bin/python')
        actual = os.stat(f'/proc/{pid}/exe')
        require((actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino), 'process_not_ready')
    except OSError:
        # UID0 without ptrace visibility is an unsupported prerequisite, never
        # permission to accept argv alone or widen root's capabilities.
        raise RouteCheckError('process_not_ready') from None

def supervised_api_identity(api_pid: int, supervisor_pid: int) -> dict:
    """Validate EXACT $!; never discover/adopt a wrapper's descendants."""
    supervisor = _process_snapshot(supervisor_pid, 0, 0)
    api = _process_snapshot(api_pid, 1800, 1800)
    command = api['command']
    require(api['ppid'] == supervisor_pid and api['pgid'] == api_pid and api['sid'] == api_pid,
        'process_not_ready')
    require(command[:3] == API_COMMAND and len(command) == 10, 'process_not_ready')
    # Host/port are private startup policy, not selectors accepted by this helper.
    require(command[3] == b'--host' and command[4] in (b'0.0.0.0', b'127.0.0.1', b'::')
        and command[5] == b'--port' and command[6].isdigit() and 0 < int(command[6]) < 65536
        and command[7:] == (b'--workers', b'1', b'--no-proxy-headers'), 'process_not_ready')
    _admitted_executable(api_pid)
    # A second proc/UID/cmdline read closes the exec/reuse window.
    require(_process_snapshot(api_pid, 1800, 1800) == api
        and _process_snapshot(supervisor_pid, 0, 0) == supervisor, 'process_not_ready')
    ticks = os.sysconf('SC_CLK_TCK')
    require(type(ticks) is int and ticks > 0, 'process_not_ready')
    return {'schema_version': 1, 'profile': PROFILE,
        'supervisor': {k: supervisor[k] for k in ('pid', 'proc_start_ticks')},
        'api': {k: api[k] for k in ('pid', 'proc_start_ticks')},
        'clock_ticks_per_second': ticks, 'phase': 'starting'}


def _tar_headers(raw: bytes) -> None:
    require(0 < len(raw) <= MAX_TAR and len(raw) % 512 == 0, 'cleanup_failed')
    offset = count = 0
    while offset < len(raw):
        block = raw[offset:offset + 512]
        if not any(block):
            require(len(raw) - offset >= 1024 and not any(raw[offset:]), 'cleanup_failed')
            return
        count += 1
        require(count <= MAX_ENTRIES, 'cleanup_failed')
        try:
            header = tarfile.TarInfo.frombuf(block, 'utf-8', 'strict')
        except (tarfile.TarError, ValueError, UnicodeError):
            raise RouteCheckError('cleanup_failed') from None
        require(header.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.XHDTYPE)
            and 0 <= header.size <= MAX_RECORD, 'cleanup_failed')
        end = offset + 512 + header.size
        padded = (end + 511) // 512 * 512
        require(padded <= len(raw) and not any(raw[end:padded]), 'cleanup_failed')
        offset = padded
    raise RouteCheckError('cleanup_failed')


def stopped_tar_records(raw: bytes) -> dict[str, bytes]:
    """Parse the fixed docker-cp tar IN MEMORY; never extract or select a path.

    This validates transport/custody only. Authoritative record types and the
    current-container join are checked separately by validate_stopped_snapshot.
    """
    _tar_headers(raw)
    expected = {'': (True, 0, 1800, 0o710), 'api': (True, 1800, 1800, 0o700),
        'lock': (False, 0, 1800, 0o640), 'supervisor.json': (False, 0, 1800, 0o640),
        'state.json': (False, 0, 1800, 0o640), 'launch.json': (False, 0, 1800, 0o640),
        'launch-status.json': (False, 0, 1800, 0o640)}
    names, records = set(), {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            for member in archive:
                require(len(names) < MAX_ENTRIES, 'cleanup_failed')
                name = member.name
                require(len(name) <= 128 and not name.startswith('/') and '\\' not in name, 'cleanup_failed')
                if name.startswith('./'):
                    name = name[2:]
                if name in ('.', ''):
                    name = ''
                require('..' not in PurePosixPath(name).parts and name in expected and name not in names,
                    'cleanup_failed')
                names.add(name)
                directory, uid, gid, mode = expected[name]
                require(member.isdir() if directory else member.isreg(), 'cleanup_failed')
                require(member.uid == uid and member.gid == gid and member.mode == mode
                    and member.size <= MAX_RECORD and (not directory or member.size == 0), 'cleanup_failed')
                require(set(member.pax_headers) <= {'atime', 'ctime', 'mtime'}
                    and all(re.fullmatch(r'-?[0-9]{1,20}(\.[0-9]{1,9})?', value)
                        for value in member.pax_headers.values()), 'cleanup_failed')
                if not directory:
                    require(member.size == 0 if name == 'lock' else member.size > 0, 'cleanup_failed')
                    content = archive.extractfile(member)
                    require(content is not None, 'cleanup_failed')
                    value = content.read(MAX_RECORD + 1)
                    require(len(value) == member.size, 'cleanup_failed')
                    records[name] = value
    except (tarfile.TarError, OSError, ValueError, UnicodeError):
        raise RouteCheckError('cleanup_failed') from None
    require(names == set(expected), 'cleanup_failed')
    return records


def validate_stopped_snapshot(raw: bytes, runtime: dict, completion_raw: bytes, docker_wait_exit_code: int) -> dict:
    """Pure comparison, not historical kernel-wait or installation authority.

    Trusted host MUST acquire tar/logs/wait from the SAME current full CID,
    StartedAt and independently validated typed image/resources under its FD.
    """
    from datetime import datetime, timezone
    shared = _shared()
    require(type(docker_wait_exit_code) is int and docker_wait_exit_code == 0, 'cleanup_failed')
    records = stopped_tar_records(raw)
    try:
        typed = {name:shared.validate_record(kind,records[name]) for name,kind in
            (('launch.json','launch'),('launch-status.json','launch_status'),
             ('supervisor.json','supervisor'),('state.json','state'))}
        require(all(shared.canonical(value) == records[name] for name,value in typed.items()), 'cleanup_failed')
        launch,status,supervisor,state = (typed[name] for name in
            ('launch.json','launch-status.json','supervisor.json','state.json'))
        purpose = shared.validate_local_backup_profile(launch)
        completion = shared.validate_completion_envelope(completion_raw,launch=launch,status=status)
        require(completion['launch_sha256'] == hashlib.sha256(records['launch.json']).hexdigest()
            and completion['status_sha256'] == hashlib.sha256(records['launch-status.json']).hexdigest(), 'cleanup_failed')
        require(all(status[key] == launch[key] for key in ('entrypoint','supervisor','api'))
            and status['phase'] == 'stopped' and status['result'] == 'clean_stop'
            and supervisor['phase'] == 'stopped' and supervisor['api'] == launch['api']
            and supervisor['supervisor'] == launch['supervisor']
            and supervisor['clock_ticks_per_second'] == launch['clock_ticks_per_second'], 'cleanup_failed')
        require(type(runtime) is dict and set(runtime) == {'container_id','started_at','image','resources_sha256'}
            and re.fullmatch(r'[0-9a-f]{64}',runtime['container_id']) is not None
            and re.fullmatch(r'[0-9a-f]{64}',runtime['resources_sha256']) is not None, 'cleanup_failed')
        image = runtime['image']
        require(type(image) is dict and set(image) == {'kind','id','config_id'}
            and image['kind'] in ('config','selected_manifest')
            and all(type(image[key]) is str and re.fullmatch(r'sha256:[0-9a-f]{64}',image[key]) is not None
                for key in ('id','config_id'))
            and (image['kind'] != 'config' or image['id'] == image['config_id']), 'cleanup_failed')
        # Docker's nanosecond UTC StartedAt is preserved, not rounded to a
        # datetime microsecond or inferred from a stale rootfs record.
        match = re.fullmatch(r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z',runtime['started_at'])
        require(match is not None, 'cleanup_failed')
        stamp = datetime.strptime(match[1],'%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
        started_ns = int(stamp.timestamp()) * 1_000_000_000 + int((match[2] or '').ljust(9,'0'))
        require(0 < started_ns <= launch['exec_utc_ns'] <= status['updated_utc_ns']
            and launch['exec_boottime_ns'] <= status['updated_boottime_ns'], 'cleanup_failed')
        disarmed = state['disarmed']
        require(state['state'] == 'disarmed' and state['arm'] is None
            and state['closing_reason'] is None and disarmed is not None, 'cleanup_failed')
        if purpose == 'normal_local_loopback':
            require(disarmed['reason'] == 'startup' and all(disarmed[key] is None
                for key in ('api','runtime_boot_nonce','runtime','operation_id')), 'cleanup_failed')
        else:
            require(disarmed['reason'] == 'shutdown' and disarmed['runtime'] == runtime
                and disarmed['runtime_boot_nonce'] is not None and disarmed['api'] == launch['api']
                and disarmed['operation_id'] is not None, 'cleanup_failed')
        return {'schema_version':1,'profile':PROFILE,'state':'stopped_disarmed',
            'readiness_profile':purpose,'operation_id':completion['operation_id'],
            'launch_sha256':completion['launch_sha256'],'status_sha256':completion['status_sha256']}
    except (shared.RouteCheckError, ValueError, KeyError, TypeError, OverflowError):
        raise RouteCheckError('cleanup_failed') from None


def _shared():
    # Production has ONE fixed protected physical module. Source-tree tests
    # explicitly inject the canonical build fixture; there is NO fallback here.
    import importlib
    import sys
    directory = Path('/usr/local/lib/volt-private')
    target = directory / 'volt_route_check_records.py'
    for path in (directory, *directory.parents, target):
        value = path.lstat()
        require(value.st_uid == 0 and not value.st_mode & 0o022 and not path.is_symlink(), 'custody_invalid')
    require(stat.S_ISREG(target.stat().st_mode) and stat.S_IMODE(target.stat().st_mode) == 0o644,
        'custody_invalid')
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))
    module = importlib.import_module('volt_route_check_records')
    require(Path(module.__file__) == target, 'custody_invalid')
    return module


def _read_input(stream, *, limit=MAX_RECORD, seconds=10):
    import select
    import time
    deadline = time.monotonic() + seconds
    result = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'invalid_input')
        ready, _, _ = select.select([stream.fileno()], [], [], remaining)
        require(bool(ready), 'invalid_input')
        block = os.read(stream.fileno(), min(4096, limit - len(result) + 1))
        if not block:
            return bytes(result)
        result.extend(block)
        require(len(result) <= limit, 'invalid_input')




def _existing_runtime(intent=None):
    """ONE canonical released-reader; no DB/key/constructor/API import."""
    shared = _shared()
    require(set(os.environ) == {'PATH','LC_ALL','UVM_LOCAL_START_IMAGE_ID','UVM_LOCAL_START_RESOURCES_SHA256'}
        and os.environ['PATH'] == '/usr/bin:/bin' and os.environ['LC_ALL'] == 'C', 'invalid_input')
    expected_image = os.environ['UVM_LOCAL_START_IMAGE_ID']
    expected_resources = os.environ['UVM_LOCAL_START_RESOURCES_SHA256']
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', expected_image) is not None
        and re.fullmatch(r'[0-9a-f]{64}', expected_resources) is not None, 'invalid_input')
    if intent is not None:
        require(intent['image']['id'] == expected_image and intent['resources_sha256'] == expected_resources,
            'identity_mismatch')
    admission = shared.load_runtime_admission(expected_image_id=expected_image,
        expected_resources_sha256=expected_resources)
    descriptor = os.open('/etc/volt/local-auth.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 1800
            and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
            and before.st_size <= 16384, 'custody_invalid')
        raw = os.read(descriptor, 16385)
        named = os.stat('/etc/volt/local-auth.json', follow_symlinks=False)
        fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        require(len(raw) == before.st_size and all(getattr(before,k) == getattr(v,k)
            for k in fields for v in (os.fstat(descriptor),named)), 'custody_invalid')
    finally:
        os.close(descriptor)
    def unique(items):
        result = {}
        for key,value in items:
            require(key not in result, 'invalid_input'); result[key] = value
        return result
    config = json.loads(raw, object_pairs_hook=unique)
    require(set(config) == {'schema_version','installation_id','public_origin','secret_source',
        'bootstrap_delivery','session_policy','trusted_ingress'} and type(config['schema_version']) is int
        and config['schema_version'] == 1 and config['trusted_ingress']['mode'] == 'https'
        and config['installation_id'] == admission['installation_id'], 'identity_mismatch')
    if intent is not None:
        require(all(intent[k] == admission[k] for k in
            ('installation_id','journal_id','restore_generation','recovery_epoch_id','resources_sha256'))
            and intent['image']['id'] == admission['image_id']
            and intent['public_origin'] == config['public_origin'], 'identity_mismatch')
    return admission


def _dead_process(identity):
    # Shared proved-dead predicate; not-ready/SIGSTOP can never authorise cleanup.
    return _shared().proc_dead(identity)


def _ready(store, arm=None):
    shared = _shared()
    supervisor = store.read_supervisor()
    shared.validate_supervision(supervisor)
    launch = store.read_launch()
    shared.validate_launch_processes(launch)
    require(launch['api'] == supervisor['api'] and launch['supervisor'] == supervisor['supervisor'],
        'identity_mismatch')
    boot = store.read_boot()
    require(boot is not None and boot['ready'] is True and boot['api'] == supervisor['api']
        and boot['published_boottime_ns'] <= shared.boottime_ns() and not store.inventory(), 'process_not_ready')
    if arm is not None:
        require(boot['runtime_boot_nonce'] == arm['runtime_boot_nonce'] and boot['api'] == arm['api']
            and boot['published_boottime_ns'] <= arm['issued_boottime_ns'], 'identity_mismatch')
    return boot


def _runtime_fields(arm):
    return {key: arm[key] for key in ('container_id', 'started_at', 'image', 'resources_sha256')}


def _disarm(store, state, reason, *, remove_boot=False):
    """Durable closing barrier, observation removal/fsync, then root completion."""
    shared = _shared()
    if state['state'] == 'armed':
        state = shared.record(state='closing', arm=state['arm'], disarmed=None, closing_reason=reason)
        store.publish_state(state)
    elif state['state'] == 'closing' and state['closing_reason'] != reason:
        # A lost-WORK completion can be cancelled, never adopted as acceptance.
        state = {**state, 'closing_reason': 'cancelled'}
        store.publish_state(state)
    store.cleanup_observations(remove_boot=remove_boot)
    if state['state'] == 'closing':
        arm = state['arm']
        disarmed = shared.record(runtime_boot_nonce=arm['runtime_boot_nonce'], api=arm['api'],
            runtime=_runtime_fields(arm), reason=state['closing_reason'], operation_id=arm['operation_id'])
        state = shared.record(state='disarmed', arm=None, disarmed=disarmed, closing_reason=None)
        store.publish_state(state)
    require(store.read_state() == state and store.read_seen() is None and not store.inventory(), 'cleanup_failed')
    return state


def execute(operation: str, raw: bytes) -> dict:
    """Fixed ROOT operation. The host caller separately retains/proves its FD."""
    import time
    shared = _shared()
    require(os.geteuid() == 0, 'custody_invalid')
    request = shared.validate_record('request', raw)
    base = {'schema_version', 'profile'}
    shapes = {'state': base, 'arm': base | {'intent'}, 'read-and-disarm': base | {'arm'},
        'cancel': base | {'operation_id', 'runtime_boot_nonce', 'api'}, 'shutdown': base | {'api'}}
    require(operation in shapes and set(request) == shapes[operation], 'invalid_input')
    if operation == 'shutdown':
        return supervisor_shutdown(request['api'])
    _existing_runtime(request.get('intent') or request.get('arm'))
    with shared.locked_store(role='root') as store:
        if operation == 'state':
            return store.current_state()
        state = store.read_state()
        if operation == 'arm':
            intent = request['intent']
            boot = _ready(store)
            require(state['state'] == 'disarmed', 'operation_conflict')
            require(intent['api'] == boot['api'] and intent['runtime_boot_nonce'] == boot['runtime_boot_nonce'],
                'identity_mismatch')
            _existing_runtime(intent)
            utc, mono, ttl = time.time_ns(), shared.boottime_ns(), intent['ttl_ns']
            arm = shared.record(**{key: value for key, value in intent.items() if key != 'ttl_ns'},
                issued_utc_ns=utc, expires_utc_ns=utc + ttl,
                issued_boottime_ns=mono, expires_boottime_ns=mono + ttl)
            shared.validate_record('arm', shared.canonical(arm))
            store.publish_state(shared.record(state='armed', arm=arm, disarmed=None, closing_reason=None))
        elif operation == 'read-and-disarm':
            arm = request['arm']
            require(state['state'] == 'armed' and state['arm'] == arm, 'operation_conflict')
            _ready(store, arm); _existing_runtime(arm); shared.check_fresh(arm)
            seen = store.read_seen()
            require(seen is not None, 'observation_missing')
            shared.validate_observation(arm, seen)
            _disarm(store, state, 'completed')
            return shared.record(operation_id=arm['operation_id'], state='observed_and_disarmed', seen=seen)
        else:
            if state['state'] == 'disarmed':
                terminal = state['disarmed']
                require(terminal['reason'] == 'cancelled' and all(terminal[key] == request[key]
                    for key in ('operation_id', 'runtime_boot_nonce', 'api')), 'operation_conflict')
            else:
                arm = state['arm']
                require(all(arm[key] == request[key] for key in ('operation_id', 'runtime_boot_nonce', 'api')),
                    'operation_conflict')
                supervisor = store.read_supervisor()
                # No observation file can turn another process into this one.
                if arm['api'] != supervisor['api']:
                    require(_dead_process(arm['api']), 'process_not_ready')
                else:
                    try:
                        boot = store.read_boot()
                    except shared.RouteCheckError as error:
                        if error.code != 'invalid_input':
                            raise
                        boot = None  # Malformed observation is cleanup data, never acceptance.
                    if boot is not None and boot['runtime_boot_nonce'] != arm['runtime_boot_nonce']:
                        require(_dead_process(arm['api']), 'process_not_ready')
                _disarm(store, state, 'cancelled')
            return shared.record(operation_id=request['operation_id'], state='cancelled')
    # Arm acknowledgement must not hold the shared inode while API refresh runs.
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        with shared.locked_store(role='root') as store:
            require(store.read_state()['state'] == 'armed' and store.read_state()['arm'] == arm,
                'operation_conflict')
            boot = _ready(store, arm); shared.check_fresh(arm)
            if boot['loaded_operation_id'] == arm['operation_id'] and time.monotonic() < deadline:
                return shared.record(arm=arm)
        time.sleep(0.05)
    raise RouteCheckError('process_not_ready')


def _broker_writer(entrypoint, supervisor):
    shared = _shared()
    require(os.geteuid() == 0 and shared.validated_proc_identity(os.getpid()) == supervisor
        and shared.validated_proc_identity(os.getppid()) == entrypoint, 'process_not_ready')
    require(shared.proc_metadata(supervisor['pid'])['uids'] == (0,)*4
        and shared.proc_metadata(entrypoint['pid'])['uids'] == (0,)*4, 'process_not_ready')
    return shared


def _optional(call, shared):
    try:
        return call()
    except shared.RouteCheckError as error:
        if error.code != 'state_inconsistent':
            raise
        return None


def broker_prepare(entrypoint, supervisor):
    shared = _broker_writer(entrypoint, supervisor)
    shared.bootstrap_store()
    with shared.locked_store(role='root') as store:
        previous = _optional(store.read_launch, shared)
        state = _optional(store.read_state, shared)
        if previous is None:
            # No partial publication can become launched authority or a new
            # identity. A dirty prepublication rootfs needs container termination.
            require(state is None and _optional(store.read_supervisor, shared) is None
                and store.read_launch_status() is None and store.read_boot() is None
                and store.read_seen() is None and not store.inventory(), 'state_inconsistent')
        else:
            require(shared.proc_dead(previous['api']) and shared.proc_dead(previous['supervisor']),
                'process_not_ready')
            require(state is not None, 'state_inconsistent')
            _disarm(store, state, 'cancelled', remove_boot=True)
        startup = shared.record(runtime_boot_nonce=None, api=None, runtime=None, reason='startup', operation_id=None)
        store.publish_state(shared.record(state='disarmed', arm=None, disarmed=startup, closing_reason=None))


def _status(shared, launch, phase, result):
    import time
    return {'schema_version':1, 'profile':shared.LAUNCH_PROFILE,
        **{k:launch[k] for k in ('entrypoint','supervisor','api')}, 'phase':phase,'result':result,
        'updated_utc_ns':time.time_ns(),'updated_boottime_ns':shared.boottime_ns()}


def broker_launched(entrypoint, supervisor, api, executable, readiness_profile):
    import time
    shared = _broker_writer(entrypoint, supervisor)
    launch = {'schema_version':1,'profile':shared.LAUNCH_RECORD_PROFILE,'recipe':shared.MAIN_API_RECIPE,
        'readiness_profile':readiness_profile,
        'entrypoint':entrypoint,'supervisor':supervisor,'api':api,
        'clock_ticks_per_second':os.sysconf('SC_CLK_TCK'),'executable':executable,
        'exec_utc_ns':time.time_ns(),'exec_boottime_ns':shared.boottime_ns()}
    with shared.locked_store(role='root') as store:
        store.publish_launch(launch)
    # The original broker retains this object until its FINAL exit. Factory
    # construction owns its own short lock and must never run inside this one.
    session = shared.broker_session(launch)
    return launch,session


def broker_begin(launch, session):
    shared = _broker_writer(launch['entrypoint'],launch['supervisor'])
    supervisor,api = launch['supervisor'],launch['api']
    session.publish_supervisor(shared.record(supervisor=supervisor,api=api,
        clock_ticks_per_second=launch['clock_ticks_per_second'],phase='starting'))
    session.publish_status(_status(shared,launch,'running','none'))


def broker_disarm(entrypoint, supervisor, api):
    """Routing cleanup only; terminal outcomes remain original-session owned."""
    shared = _broker_writer(entrypoint,supervisor)
    with shared.locked_store(role='root') as store:
        _checked_launch(store,entrypoint,supervisor,api)
        state = _disarm(store,store.read_state(),'shutdown',remove_boot=True)
        prior = state['disarmed']
        if prior['api'] == api and prior['runtime_boot_nonce'] is not None:
            store.publish_state({**state,'disarmed':{**prior,'reason':'shutdown'}})


def _checked_launch(store, entrypoint, supervisor, api):
    launch = store.read_launch()
    require(all(launch[k] == v for k,v in (('entrypoint',entrypoint),('supervisor',supervisor),('api',api))),
        'identity_mismatch')
    return launch


def _entrypoint_writer(store):
    shared = _shared()
    require(os.geteuid() == 0, 'custody_invalid')
    launch = store.read_launch()
    require(shared.validated_proc_identity(os.getppid()) == launch['entrypoint']
        and shared.proc_metadata(os.getppid())['uids'] == (0,)*4, 'process_not_ready')
    return shared,launch


def entrypoint_launch_pid():
    shared = _shared()
    with shared.locked_store(role='root') as store:
        _,launch = _entrypoint_writer(store)
        shared.validate_launch_processes(launch)
        wire = store.read_supervisor();status = store.read_launch_status()
        require(wire['api'] == launch['api'] and wire['supervisor'] == launch['supervisor']
            and wire['phase'] in ('starting','ready') and status is not None
            and status['phase'] == 'running' and status['result'] == 'none', 'process_not_ready')
        return launch['api']['pid']


def entrypoint_ready():
    shared = _shared()
    with shared.locked_store(role='root') as store:
        _,launch = _entrypoint_writer(store)
        require(store.read_broker_ready() is True, 'process_not_ready')


def entrypoint_verification_health():
    shared = _shared()
    with shared.locked_store(role='root') as store:
        _entrypoint_writer(store)
        require(store.read_verification_health() is True, 'process_not_ready')


def entrypoint_api_stop_progress():
    shared = _shared()
    with shared.locked_store(role='root') as store:
        _entrypoint_writer(store)
        progress = store.read_api_stop_progress()
        require(progress is not None, 'process_not_ready')
        return shared.canonical(progress)


def entrypoint_private_encoding(action, operation=None):
    """Fixed read-only encoders. Bytes never certify a completed kernel wait."""
    import secrets
    shared = _shared()
    require(action in ('stop-operation','terminal-success','terminal-failure','completion-request'), 'invalid_input')
    with shared.locked_store(role='root') as store:
        _,launch = _entrypoint_writer(store)
        require(shared.proc_live(launch['entrypoint']), 'process_not_ready')
        if action == 'stop-operation':
            require(operation is None, 'invalid_input')
            return secrets.token_hex(32).encode('ascii')
        require(type(operation) is bytes and re.fullmatch(b'[0-9a-f]{64}',operation) is not None, 'invalid_input')
        value = {'schema_version':1, 'profile':shared.COMPLETION_REQUEST_PROFILE if action == 'completion-request' else shared.TERMINAL_PROFILE,
            **{key:launch[key] for key in ('entrypoint','supervisor','api')}, 'operation_id':operation.decode('ascii')}
        if action != 'completion-request':
            require(shared.proc_live(launch['supervisor']), 'process_not_ready')
            value.update(result='success' if action == 'terminal-success' else 'failure',
                reason='none' if action == 'terminal-success' else 'service_cleanup_failed')
        raw = shared.canonical(value)
        shared.validate_record('completion_request' if action == 'completion-request' else 'terminal',raw)
        require(len(raw) <= 2048, 'state_inconsistent')
        return raw


def _cleanup_api_identity(api):
    # Cleanup of an ORIGINAL registered stopped API is permitted; stopped is
    # never readiness/death. No descendant discovery or caller-supplied PID.
    before = parse_proc_stat(_proc_bytes(api['pid'],'stat'),api['pid'],cleanup_only=True)
    require({k:before[k] for k in ('pid','proc_start_ticks')} == api
        and before['pgid'] == api['pid'] and before['sid'] == api['pid'], 'identity_mismatch')
    status = _proc_bytes(api['pid'],'status')
    for key in (b'Uid',b'Gid'):
        lines = [v for v in status.splitlines() if v.startswith(key+b':')]
        require(len(lines) == 1 and lines[0].split(b':',1)[1].split() == [b'1800']*4,
            'identity_mismatch')
    after = parse_proc_stat(_proc_bytes(api['pid'],'stat'),api['pid'],cleanup_only=True)
    require(before == after, 'process_not_ready')



def entrypoint_signal_broker(kind):
    import select
    import signal
    shared = _shared()
    require(kind in ('stop','quiesce','kill'), 'invalid_input')
    with shared.locked_store(role='root') as store:
        _,launch = _entrypoint_writer(store)
        target = launch['supervisor']
        if shared.proc_dead(target):
            return False
        def checked():
            value = parse_proc_stat(_proc_bytes(target['pid'],'stat'),target['pid'],cleanup_only=True)
            require({k:value[k] for k in ('pid','proc_start_ticks')} == target
                and value['ppid'] == launch['entrypoint']['pid'], 'identity_mismatch')
            status = _proc_bytes(target['pid'],'status')
            for key in (b'Uid',b'Gid'):
                lines = [line for line in status.splitlines() if line.startswith(key+b':')]
                require(len(lines) == 1 and lines[0].split(b':',1)[1].split() == [b'0']*4,
                    'identity_mismatch')
            return value
        before = checked();descriptor = os.pidfd_open(target['pid'],0)
        try:
            require(before == checked() and not select.select([descriptor],[],[],0)[0], 'process_not_ready')
            signal.pidfd_send_signal(descriptor,{'stop':signal.SIGTERM,'quiesce':signal.SIGUSR1,'kill':signal.SIGKILL}[kind],None,0)
        finally:
            os.close(descriptor)
        return True


def entrypoint_latch_quiesce():
    shared = _shared()
    with shared.locked_store(role='root') as store:
        _,launch = _entrypoint_writer(store)
        status = store.read_launch_status()
        require(status is not None, 'state_inconsistent')
        # This external helper has NO outcome-writing or poison RPC authority.
        # PID1 keeps its own sticky failure and cannot clean-seal broker loss.
        require(status['phase'] in ('quiesce_failed','api_stopped','stopped'), 'process_not_ready')


def entrypoint_quiesce_surviving():
    shared = _shared()
    with shared.locked_store(role='root') as store:
        _,launch = _entrypoint_writer(store);status = store.read_launch_status()
        require(status is not None, 'state_inconsistent')
        broker_dead,api_dead = shared.proc_dead(launch['supervisor']),shared.proc_dead(launch['api'])
        return not broker_dead and (not api_dead or store.read_api_stop_progress() is not None)


def entrypoint_quiesce_timeout():
    """Typed original-broker timeout only, never readiness or dead inference."""
    shared = _shared()
    with shared.locked_store(role='root') as store:
        _,launch = _entrypoint_writer(store)
        status = store.read_launch_status();wire = store.read_supervisor()
        require(status is not None and all(status[key] == launch[key]
            for key in ('entrypoint','supervisor','api')) and status['phase'] == 'quiesce_failed'
            and status['result'] == 'quiesce_timeout' and wire['phase'] == 'failed'
            and wire['api'] == launch['api'] and wire['supervisor'] == launch['supervisor']
            and wire['clock_ticks_per_second'] == launch['clock_ticks_per_second']
            and shared.proc_live(launch['supervisor']) and not shared.proc_dead(launch['api']), 'process_not_ready')
        _cleanup_api_identity(launch['api'])
        return True

def _clean_registered_stop(store, launch, status, shared):
    """Complete same-launch clean join; never reconstruct partial authority.

    The all-null startup disarm proves no bound routing operation, not HTTPS
    routing/backup. Bound operation evidence has the stricter existing join.
    """
    require(status is not None and all(status[k] == launch[k]
        for k in ('entrypoint','supervisor','api')) and status['phase'] == 'stopped'
        and status['result'] == 'clean_stop', 'cleanup_failed')
    wire = store.read_supervisor()
    require(wire['phase'] == 'stopped' and wire['api'] == launch['api']
        and wire['supervisor'] == launch['supervisor']
        and wire['clock_ticks_per_second'] == launch['clock_ticks_per_second'], 'cleanup_failed')
    require(shared.proc_dead(launch['api']) and shared.proc_dead(launch['supervisor']), 'cleanup_failed')
    state = store.read_state();boot = store.read_boot()
    require(state['state'] == 'disarmed' and state['arm'] is None
        and state['closing_reason'] is None and state['disarmed'] is not None
        and store.read_seen() is None and not store.inventory(), 'cleanup_failed')
    disarmed = state['disarmed']
    if disarmed['api'] is None:
        require(disarmed['reason'] == 'startup' and all(disarmed[k] is None
            for k in ('runtime_boot_nonce','runtime','operation_id')) and boot is None, 'cleanup_failed')
    else:
        require(disarmed['api'] == launch['api'] and disarmed['reason'] == 'shutdown'
            and disarmed['runtime_boot_nonce'] is not None and disarmed['runtime'] is not None,
            'cleanup_failed')
        if boot is not None:
            require(boot['api'] == launch['api'] and boot['ready'] is False
                and boot['loaded_operation_id'] is None
                and boot['runtime_boot_nonce'] == disarmed['runtime_boot_nonce'], 'cleanup_failed')
    return True


def entrypoint_orphan_cleanup():
    import select
    import signal
    import time
    shared = _shared()
    # Full root launch is the ONLY target authority. Missing/partial launch
    # requires whole-container termination, never a proposed/discovered API R.
    with shared.locked_store(role='root') as store:
        _,launch = _entrypoint_writer(store)
        require(shared.proc_dead(launch['supervisor']), 'process_not_ready')
        api = launch['api'];status = store.read_launch_status()
        # Candidate files cannot authorize clean broker loss. Only original
        # Bash's actual adapter/broker waits and completion producer can do so.
    forced = False
    if not shared.proc_dead(api):
        _cleanup_api_identity(api)
        descriptor = os.pidfd_open(api['pid'],0)
        try:
            _cleanup_api_identity(api)
            require(not select.select([descriptor],[],[],0)[0], 'process_not_ready')
            signal.pidfd_send_signal(descriptor,signal.SIGTERM,None,0)
            if not select.select([descriptor],[],[],30)[0]:
                forced = True
                signal.pidfd_send_signal(descriptor,signal.SIGKILL,None,0)
                require(bool(select.select([descriptor],[],[],2)[0]), 'cleanup_failed')
        finally:
            os.close(descriptor)
    require(shared.proc_dead(api), 'cleanup_failed')
    with shared.locked_store(role='root') as store:
        _,current = _entrypoint_writer(store)
        require(current == launch, 'identity_mismatch')
        try:
            wire = store.read_supervisor()
        except shared.RouteCheckError as error:
            if error.code not in ('invalid_input','state_inconsistent'):
                raise
            wire = None  # CLEANUP ONLY, no supervisor reconstruction.
        if wire is not None:
            require(wire['api'] == api and wire['supervisor'] == launch['supervisor'], 'identity_mismatch')
        _disarm(store,store.read_state(),'api_dead',remove_boot=True)
    return False  # Unexpected broker loss can never acquire clean-backup credit.


def entrypoint_orphan_terminated():
    """Exact API termination/disarm permits DB teardown, NEVER clean sealing."""
    entrypoint_orphan_cleanup()
    shared = _shared()
    with shared.locked_store(role='root') as store:
        _,launch = _entrypoint_writer(store)
        state = store.read_state()
        require(shared.proc_dead(launch['supervisor']) and shared.proc_dead(launch['api'])
            and state['state'] == 'disarmed' and state['arm'] is None
            and state['closing_reason'] is None and state['disarmed'] is not None
            and store.read_boot() is None and store.read_seen() is None and not store.inventory(), 'cleanup_failed')
        disarmed = state['disarmed']
        if disarmed['api'] is None:
            require(disarmed['reason'] == 'startup' and all(disarmed[key] is None
                for key in ('runtime_boot_nonce','runtime','operation_id')), 'cleanup_failed')
        else:
            require(disarmed['api'] == launch['api'], 'identity_mismatch')
        return True


def launch_status():
    shared = _shared()
    require(os.geteuid() == 0, 'custody_invalid')
    with shared.locked_store(role='root') as store:
        launch = store.read_launch();status = store.read_launch_status()
        require(status is not None and all(status[k] == launch[k] for k in ('entrypoint','supervisor','api')),
            'state_inconsistent')
        return status

def supervisor_shutdown(api=None):
    # Old direct-parent supervisor calls are forbidden after the broker delta.
    # The fixed protected broker owns its pidfd and finite lifecycle callbacks.
    raise RouteCheckError('invalid_input')


def _main():
    import sys
    require(len(sys.argv) == 2 and sys.argv[1] in
        ('state', 'arm', 'read-and-disarm', 'cancel', 'shutdown'), 'invalid_input')
    result = execute(sys.argv[1], _read_input(sys.stdin.buffer))
    raw = _shared().canonical(result)
    require(len(raw) <= MAX_RECORD, 'state_inconsistent')
    sys.stdout.buffer.write(raw + b'\n')


def _entrypoint_main(action):
    import sys
    require(os.geteuid() == 0 and dict(os.environ) == {'PATH':'/usr/bin:/bin','LC_ALL':'C'}, 'custody_invalid')
    if action == 'entrypoint-launch-pid':
        value = entrypoint_launch_pid()
        require(type(value) is int and 0 < value <= 2147483647, 'state_inconsistent')
        sys.stdout.write(str(value)+'\n')
    elif action == 'entrypoint-ready':
        entrypoint_ready()
    elif action == 'entrypoint-verification-health':
        entrypoint_verification_health()
    elif action == 'entrypoint-api-stop-progress':
        sys.stdout.buffer.write(entrypoint_api_stop_progress())
    elif action == 'entrypoint-stop-operation':
        sys.stdout.buffer.write(entrypoint_private_encoding('stop-operation'))
    elif action in ('entrypoint-terminal-success','entrypoint-terminal-failure','entrypoint-completion-request'):
        operation = _read_input(sys.stdin.buffer,limit=64,seconds=2)
        sys.stdout.buffer.write(entrypoint_private_encoding(action.removeprefix('entrypoint-'),operation))
    elif action == 'entrypoint-signal-stop':
        require(entrypoint_signal_broker('stop') is True, 'process_not_ready')
    elif action == 'entrypoint-signal-quiesce':
        require(entrypoint_signal_broker('quiesce') is True, 'process_not_ready')
    elif action == 'entrypoint-signal-kill':
        require(entrypoint_signal_broker('kill') is True, 'process_not_ready')
    elif action == 'entrypoint-orphan-cleanup':
        require(entrypoint_orphan_cleanup() is True, 'cleanup_failed')
    elif action == 'entrypoint-latch-quiesce':
        entrypoint_latch_quiesce()
    elif action == 'entrypoint-quiesce-surviving':
        require(entrypoint_quiesce_surviving() is True, 'process_not_ready')
    elif action == 'entrypoint-quiesce-timeout':
        require(entrypoint_quiesce_timeout() is True, 'process_not_ready')
    elif action == 'entrypoint-orphan-terminated':
        require(entrypoint_orphan_terminated() is True, 'cleanup_failed')
    else:
        raise RouteCheckError('invalid_input')


def _dispatch():
    import sys
    require(len(sys.argv) == 2, 'invalid_input')
    if sys.argv[1] in ('health-normal','health-verification'):
        require(os.geteuid() == 0 and dict(os.environ) == {'PATH':'/usr/bin:/bin','LC_ALL':'C'}, 'custody_invalid')
        shared = _shared()
        with shared.locked_store(role='root') as store:
            result = store.read_broker_ready() if sys.argv[1] == 'health-normal' else store.read_verification_health()
            require(result is True, 'process_not_ready')
    elif sys.argv[1].startswith('entrypoint-'):
        _entrypoint_main(sys.argv[1])
    else:
        _main()


def finite_error_code(error):
    import sys
    # Only the two fixed typed implementations supply semantic codes. An
    # unexpected exception's arbitrary .code/property/message is never used.
    expected = type(error) is RouteCheckError
    canonical = sys.modules.get('volt_route_check_records')
    if canonical is not None:
        expected = expected or type(error) is getattr(canonical,'RouteCheckError',None)
    if expected:
        code = error.code
        if type(code) is str and code in ERROR_CODES:
            return code
    return 'cleanup_failed'


def _run():
    import sys
    try:
        _dispatch()
        return 0
    except Exception as error:
        sys.stderr.write('route_check_failed:'+finite_error_code(error)+'\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(_run())
