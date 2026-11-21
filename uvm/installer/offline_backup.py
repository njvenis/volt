"""Fixed read-only store inventories and private numeric-owner tar capture."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile

STORES = ('postgres', 'media', 'state', 'instance')
MAX_ENTRIES = 250000
MAX_BYTES = 64 * 1024 * 1024 * 1024
MAX_MEMBER = 32 * 1024 * 1024 * 1024
SOURCE = Path('/restore')
DESTINATION = Path('/backup')


def _paths(root: Path) -> list[Path]:
    paths, pending = [root], [root]
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                if len(paths) >= MAX_ENTRIES:
                    raise ValueError('offline store inventory exceeds entry bound')
                path = Path(entry.path)
                paths.append(path)
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
    return [root, *sorted(path for path in paths if path != root)]


def _result(records: dict, postgres_version: str | None) -> dict:
    if '' not in records or len(records) > MAX_ENTRIES:
        raise ValueError('offline store lacks a bounded root inventory')
    checksum = hashlib.sha256()
    for name in ['', *sorted((name for name in records if name), key=PurePosixPath)]:
        checksum.update(json.dumps(records[name], separators=(',', ':')).encode() + b'\n')
    return {'sha256': checksum.hexdigest(), 'entries': len(records) - 1,
            'postgres_version': postgres_version}


def inventory(root: Path) -> dict:
    records, total, version = {}, 0, None
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError('offline store root is not a directory')
    for path in _paths(root):
        if len(records) >= MAX_ENTRIES:
            raise ValueError('offline store inventory exceeds entry bound')
        info = path.lstat()
        kind = stat.S_IFMT(info.st_mode)
        content = None
        if stat.S_ISREG(info.st_mode):
            if info.st_size > MAX_MEMBER:
                raise ValueError('offline store member exceeds size bound')
            total += info.st_size
            if total > MAX_BYTES:
                raise ValueError('offline store exceeds total size bound')
            checksum = hashlib.sha256()
            is_version = path == root / 'PG_VERSION'
            if is_version and info.st_size > 32:
                raise ValueError('offline PostgreSQL version exceeds bound')
            version_bytes = bytearray()
            descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(descriptor, 'rb') as stream:
                before = os.fstat(stream.fileno())
                fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                if any(getattr(before, field) != getattr(info, field) for field in fields):
                    raise ValueError('offline inventory file changed before read')
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    checksum.update(block)
                    if is_version:
                        version_bytes.extend(block)
                if any(getattr(before, field) != getattr(after, field)
                        for after in (os.fstat(stream.fileno()), path.lstat()) for field in fields):
                    raise ValueError('offline inventory file changed during read')
            if is_version:
                version = version_bytes.decode().strip()
            content = checksum.hexdigest()
        elif stat.S_ISLNK(info.st_mode):
            content = os.readlink(path)
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError('unsupported special file in offline store')
        name = '' if path == root else str(path.relative_to(root))
        records[name] = [name or '.', kind, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid, content]
    return _result(records, version)


class _BoundedTarInfo(tarfile.TarInfo):
    def _proc_pax(self, archive):
        if self.size > 64 * 1024:
            raise ValueError('captured archive extended metadata exceeds bound')
        return super()._proc_pax(archive)

    def _proc_gnulong(self, archive):
        if self.size > 8192:
            raise ValueError('captured archive long name exceeds bound')
        return super()._proc_gnulong(archive)


@contextmanager
def _archive_source(path: Path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_BYTES:
            raise ValueError('captured archive type or size differs')
        yield stream
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(before, key) != getattr(after, key)
                for after in (os.fstat(stream.fileno()), path.lstat()) for key in fields):
            raise ValueError('captured archive changed during validation')


def archive_inventory(path: Path) -> dict:
    """Independently compare captured tar metadata/content with RO inventories."""
    records, total, version, symlinks = {}, 0, None, set()
    with _archive_source(path) as source, tarfile.open(fileobj=source, mode='r:', tarinfo=_BoundedTarInfo) as archive:
        for member in archive:
            parts = PurePosixPath(member.name).parts
            if (member.name.startswith('/') or '..' in parts or '\x00' in member.name
                    or len(member.name) > 4096 or len(records) >= MAX_ENTRIES
                    or member.size < 0 or member.size > MAX_MEMBER
                    or member.uid < 0 or member.gid < 0):
                raise ValueError('captured archive member is unsafe or oversized')
            name = '/'.join(part for part in parts if part != '.')
            if name in records:
                raise ValueError('captured archive contains duplicate paths')
            content = None
            if member.isdir():
                kind = stat.S_IFDIR
            elif member.issym():
                kind, content = stat.S_IFLNK, member.linkname
                target = PurePosixPath(content)
                depth = len(PurePosixPath(name).parent.parts)
                if target.is_absolute():
                    raise ValueError('captured archive link escapes the store')
                for part in target.parts:
                    depth += -1 if part == '..' else 0 if part == '.' else 1
                    if depth < 0:
                        raise ValueError('captured archive link escapes the store')
                symlinks.add(name)
            elif member.isfile():
                kind = stat.S_IFREG
                total += member.size
                if total > MAX_BYTES:
                    raise ValueError('captured archive exceeds total bound')
                checksum = hashlib.sha256()
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError('captured archive content is missing')
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    checksum.update(block)
                content = checksum.hexdigest()
                if name == 'PG_VERSION':
                    if member.size > 32:
                        raise ValueError('captured PostgreSQL version is malformed')
                    version = archive.extractfile(member).read().decode().strip()
            else:
                raise ValueError('captured archive contains hardlink or special file')
            records[name] = [name or '.', kind, member.mode & 0o7777, member.uid, member.gid, content]
    if records.get('', [None, None])[1] != stat.S_IFDIR:
        raise ValueError('captured archive root is not a directory')
    if any(str(parent) in symlinks for name in records for parent in PurePosixPath(name).parents):
        raise ValueError('captured archive traverses a symbolic-link parent')
    return _result(records, version)


def capture(store: str) -> None:
    if store not in STORES:
        raise ValueError('unknown fixed offline store')
    root, destination = SOURCE, DESTINATION
    info = destination.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('private capture destination custody differs')
    path = destination / (store + '.tar')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        # The source and destination are fixed mounts. Never accept a command,
        # tar path, extraction target or source selector from request data.
        result = subprocess.run(['tar', '--numeric-owner', '-cpf', '-', '-C', str(root), '.'],
            stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.DEVNULL, timeout=900)
        if result.returncode:
            raise ValueError('fixed offline tar capture failed')
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), 0o600)
        os.fchown(stream.fileno(), info.st_uid, info.st_gid)
    directory = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('inventory', 'capture'))
    parser.add_argument('--store', choices=STORES)
    args = parser.parse_args()
    if args.operation == 'capture':
        capture(args.store)
    else:
        print(json.dumps(inventory(SOURCE), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
