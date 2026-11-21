"""Own one lifecycle FD; optionally perform fixed initialization before ready."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import types

INSTANCE_ROOT = Path('/state')
INITIAL_REQUEST = Path('/run/volt-initialization/request.json')
INITIAL_SETUP = Path('/package/setup.py')
MAX_REQUEST = 64 * 1024
OFFLINE_ACTIONS = {
    '--offline-backup-record': 'backup-record',
    '--offline-restore-provision': 'restore-provision',
    '--offline-restore-admit': 'restore-admit',
}


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate initialization field')
        value[key] = item
    return value


def _bounded_file(path: Path, limit: int, *, private: bool) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit
                or before.st_uid != os.getuid() or (private and stat.S_IMODE(before.st_mode) != 0o600)):
            raise ValueError('fixed initialization input custody differs')
        data = stream.read(limit + 1)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (len(data) != before.st_size or any(getattr(before, field) != getattr(after, field)
                for after in (os.fstat(stream.fileno()), path.stat(follow_symlinks=False)) for field in fields)):
            raise ValueError('fixed initialization input changed')
        return data


def initialize_local(fd: int) -> None:
    request_raw = _bounded_file(INITIAL_REQUEST, MAX_REQUEST, private=True)
    document = json.loads(request_raw, object_pairs_hook=_pairs)
    if (not isinstance(document, dict) or set(document) != {'schema_version', 'profile', 'arguments', 'setup_sha256'}
            or type(document['schema_version']) is not int or document['schema_version'] != 1
            or document['profile'] != 'volt_local_runtime_init_v1'):
        raise ValueError('fixed initialization request schema differs')
    code = _bounded_file(INITIAL_SETUP, 1024 * 1024, private=False)
    if document['setup_sha256'] != 'sha256:' + hashlib.sha256(code).hexdigest():
        raise ValueError('fixed admitted package setup bytes changed after emission')
    # Load only the fixed readonly package implementation already authenticated
    # by the independent bundle/graph admission. No request supplies code/path.
    module = types.ModuleType('_volt_fixed_initial_setup')
    module.__file__ = str(INITIAL_SETUP)
    exec(compile(code, str(INITIAL_SETUP), 'exec'), module.__dict__)
    args = module.runtime_init_arguments(document, INSTANCE_ROOT)
    module.init(args, lifecycle_lock_fd=fd, initial_request_raw=request_raw)


def main() -> int:
    if (len(sys.argv) not in (2, 3) or (len(sys.argv) == 3
            and sys.argv[2] not in ('--initialize-local', '--diagnostics', *OFFLINE_ACTIONS))):
        return 64
    path = Path(sys.argv[1])
    initializing = len(sys.argv) == 3 and sys.argv[2] == '--initialize-local'
    offline = OFFLINE_ACTIONS.get(sys.argv[2]) if len(sys.argv) == 3 else None
    diagnostic = len(sys.argv) == 3 and sys.argv[2] == '--diagnostics'
    if (initializing or offline or diagnostic) and path != INSTANCE_ROOT / '.install.lock':
        return 64
    if offline == 'restore-provision':
        from uvm.installer.recovery_authority import _host_writer
        _host_writer(INSTANCE_ROOT)
    try:
        flags = os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW
        if initializing:
            flags |= os.O_CREAT
        fd = os.open(path, flags, 0o600)
    except OSError:
        print('lifecycle-lock-initialization-failed', file=sys.stderr, flush=True)
        return 70
    try:
        info = os.fstat(fd)
        current = path.stat(follow_symlinks=False)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size != 0
                or any(getattr(info, field) != getattr(current, field) for field in fields)):
            raise ValueError('private lifecycle lock custody differs')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('lock-held', flush=True)
            return 75
        current = path.stat(follow_symlinks=False)
        if any(getattr(info, field) != getattr(current, field) for field in fields):
            raise ValueError('private lifecycle lock inode changed')
        if diagnostic:
            from uvm.installer.diagnostics import serve
            serve(fd)
        elif initializing:
            initialize_local(fd)
        elif offline:
            from uvm.installer.offline_lifecycle import execute
            execute(fd, offline)
        # Initialization, if selected, has succeeded on this actual held FD.
        print('locked=1', flush=True)
        while True:
            time.sleep(3600)
    except (Exception, SystemExit) as exc:
        message = 'offline-lifecycle-failed: ' + str(exc) if offline else 'lifecycle-lock-initialization-failed'
        print(message, file=sys.stderr, flush=True)
        return 70
    finally:
        os.close(fd)


if __name__ == '__main__':
    raise SystemExit(main())
