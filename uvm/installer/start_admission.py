"""Root-only, closed local-start admission and host release handshake."""
from __future__ import annotations
import argparse
import ctypes
import errno
import hashlib
import json
import os
import secrets
from pathlib import Path
import re
import select
import stat
import sys
import time
import uuid

PROFILE = 'volt_local_recovery_v1'
FIELDS = {'schema_version', 'profile', 'document_type', 'installation_id', 'journal_id',
          'restore_generation', 'recovery_epoch_id', 'image_id', 'resources_sha256', 'initial_preparation', 'local_auth_config_sha256'}
DIRECTORY = Path('/run/volt-start-admission')
RELEASE = Path('/run/uvm-maintenance/host-start-release.json')


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate start admission member')
        result[key] = value
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def validate_record(value):
    if (not isinstance(value, dict) or set(value) != FIELDS
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['profile'] != PROFILE or value['document_type'] != 'local_start_admission_v2'
            or type(value['restore_generation']) is not int or value['restore_generation'] < 0
            or type(value['initial_preparation']) is not bool
            or type(value['local_auth_config_sha256']) is not str
            or re.fullmatch(r'[0-9a-f]{64}', value['local_auth_config_sha256']) is None
            or not isinstance(value['image_id'], str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', value['image_id'])
            or not isinstance(value['resources_sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', value['resources_sha256'])):
        raise ValueError('closed local start admission invalid')
    for key in ('installation_id', 'journal_id'):
        if not isinstance(value[key], str) or str(uuid.UUID(value[key])) != value[key]:
            raise ValueError('start identity invalid')
    if value['restore_generation'] == 0:
        if value['recovery_epoch_id'] is not None:
            raise ValueError('initial start has an epoch')
    elif (not isinstance(value['recovery_epoch_id'], str)
          or str(uuid.UUID(value['recovery_epoch_id'])) != value['recovery_epoch_id']):
        raise ValueError('restore start epoch invalid')
    if value['initial_preparation'] and value['restore_generation'] != 0:
        raise ValueError('restored start cannot initialize')
    return value


def private_read(path: Path, owner: int, limit=16384, *, readonly=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != owner or before.st_nlink != 1 or before.st_size > limit
                or (readonly and not os.fstatvfs(stream.fileno()).f_flag & os.ST_RDONLY)):
            raise ValueError('start input custody invalid')
        raw = stream.read(limit + 1)
        current = path.stat(follow_symlinks=False)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if (len(raw) != before.st_size or any(getattr(before, field) != getattr(candidate, field)
                for candidate in (current, os.fstat(stream.fileno())) for field in fields)):
            raise ValueError('start input changed during read')
        return raw


def read_host_record(root: Path, metadata: dict, *, allow_unprepared=False):
    directory = root / 'secrets/local-start-admission'
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != root.stat().st_uid:
        raise ValueError('host start admission directory unsafe')
    names = {item.name for item in directory.iterdir()}
    pinned = metadata.get('local_start_admission')
    if not names and allow_unprepared and (pinned is None or metadata.get("local_start_record_pending")):
        return None
    if names != {'admission.json'}:
        raise ValueError('host start admission inventory differs')
    record = validate_record(json.loads(private_read(directory / 'admission.json', root.stat().st_uid), object_pairs_hook=pairs))
    if record != pinned:
        # A crash after durable disarming can only reconcile forwards. Never
        # infer initial permission again from a still-unacknowledged journal.
        if not (isinstance(pinned, dict) and pinned.get('initial_preparation') is True
                and record == {**pinned, 'initial_preparation': False}):
            raise ValueError('host start admission differs from journal')
    if (not isinstance(metadata.get('local_start_resources'), dict)
            or record['resources_sha256'] != hashlib.sha256(canonical(metadata['local_start_resources'])).hexdigest()
            or metadata.get('local_start_admission_sha256') != hashlib.sha256(canonical(pinned)).hexdigest()
            or record['image_id'] != metadata['image_admission']['id']
            or record['local_auth_config_sha256'] != metadata.get('local_auth_config_sha256')
            or hashlib.sha256(private_read(root / 'local-auth.json', root.stat().st_uid)).hexdigest() != record['local_auth_config_sha256']
            or any(record[key] != metadata['local_recovery_custody'][key]
                   for key in ('installation_id', 'journal_id', 'restore_generation', 'recovery_epoch_id'))):
        raise ValueError('host start admission identity changed')
    if metadata.get('established') and record['initial_preparation']:
        raise ValueError('established host retains initial permission')
    return record


def protected_records():
    # Runtime is a fixed root-protected COPY, never a source/package fallback.
    if (os.geteuid() != 0 or not sys.flags.isolated or not sys.flags.no_site
            or set(os.environ) != {'PATH','LC_ALL','UVM_LOCAL_START_IMAGE_ID','UVM_LOCAL_START_RESOURCES_SHA256'}
            or os.environ['PATH'] != '/usr/bin:/bin' or os.environ['LC_ALL'] != 'C'):
        raise ValueError('protected start environment invalid')
    directory = Path('/usr/local/lib/volt-private')
    target = directory / 'volt_route_check_records.py'
    for path in (target, *target.parents, Path('/usr/local/libexec/volt-start-admission.py'), Path('/usr/local/bin/python3.14')):
        for part in (path, *path.parents):
            value = part.lstat()
            if value.st_uid != 0 or value.st_mode & 0o022 or stat.S_ISLNK(value.st_mode):
                raise ValueError('protected start closure invalid')
    if not target.is_file() or stat.S_IMODE(target.stat().st_mode) != 0o644:
        raise ValueError('protected start module invalid')
    sys.path.insert(0,str(directory))
    import volt_route_check_records
    if Path(volt_route_check_records.__file__) != target:
        raise ValueError('protected start module differs')
    return volt_route_check_records


def load_runtime():
    shared = protected_records()
    return shared.load_start_admission(expected_image_id=os.environ['UVM_LOCAL_START_IMAGE_ID'],
        expected_resources_sha256=os.environ['UVM_LOCAL_START_RESOURCES_SHA256'])


def release():
    deadline = time.monotonic() + 5
    parts = bytearray()
    while True:
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([sys.stdin.buffer.fileno()], [], [], left)[0]:
            raise ValueError('bounded host release input timed out')
        block = os.read(sys.stdin.buffer.fileno(), min(4096,16385-len(parts)))
        if not block:
            break
        parts.extend(block)
        if len(parts) > 16384:
            raise ValueError('host release exceeds bound')
    raw = bytes(parts)
    value = validate_record(json.loads(raw, object_pairs_hook=pairs))
    current = load_runtime()
    if value != current or value['initial_preparation']:
        raise ValueError('host release differs from disarmed live admission')
    temporary = RELEASE.with_name('.host-start-release.' + secrets.token_hex(8))
    parent = os.open(RELEASE.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(temporary.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
        # Atomic no-replace avoids an unrecoverable nlink2 kill window. No
        # hardlink/syscall fallback, replacement or adoption of another value.
        libc = ctypes.CDLL(None,use_errno=True)
        rename = libc.renameat2
        rename.argtypes = (ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
        rename.restype = ctypes.c_int
        if rename(parent,os.fsencode(temporary.name),parent,os.fsencode(RELEASE.name),1) != 0:
            if ctypes.get_errno() != errno.EEXIST:
                raise ValueError('atomic host release unavailable')
            if json.loads(private_read(RELEASE,0), object_pairs_hook=pairs) != value:
                raise ValueError('root host release changed')
        os.fsync(parent)
    finally:
        try:os.unlink(temporary.name,dir_fd=parent)
        except FileNotFoundError:pass
        os.close(parent)
    print('host_start_release=recorded')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=('check', 'wait-release', 'release'))
    args = parser.parse_args()
    if args.operation == 'release':
        release(); return
    value = load_runtime()
    if args.operation == 'check':
        if value['initial_preparation']:
            # A stale initial record cannot authorize automatic Docker retries.
            # A controlled host retry recreates the container after journal checks.
            marker = Path('/run/uvm-maintenance/initial-start-consumed')
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, canonical(value)); os.fsync(fd)
            finally:
                os.close(fd)
            fd = os.open(marker.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        print(int(value['initial_preparation'])); return
    deadline = time.monotonic() + 360
    while time.monotonic() < deadline:
        current = load_runtime()
        if not current['initial_preparation'] and RELEASE.exists():
            if json.loads(private_read(RELEASE, 0), object_pairs_hook=pairs) != current:
                raise ValueError('host release does not bind current start')
            return
        time.sleep(0.2)
    raise ValueError('bounded host start release timed out')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('local start admission failed closed', file=sys.stderr)
        raise SystemExit(1) from None
