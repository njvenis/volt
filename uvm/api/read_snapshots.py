"""Private, bounded, volatile pagination snapshots shared by local API workers.

Only captured IDs/order keys and their principal/grant binding are cached here.
Current rows and authority are still rechecked by the read API. The container
entrypoint clears this directory before starting its worker set; this is not
application persistence or an external cache service.
"""
from contextlib import contextmanager
from datetime import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time

from fastapi import HTTPException


class SharedReadSnapshots:
    def __init__(self, directory, *, row_max, count_max, ttl_seconds):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, exist_ok=True)
        info = self.directory.lstat()
        if (not self.directory.is_absolute() or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise RuntimeError('read snapshot directory must be private and owned by the API user')
        self.row_max, self.count_max, self.ttl_seconds = row_max, count_max, ttl_seconds
        self._thread_lock = threading.Lock()

    @staticmethod
    def _invalid():
        raise HTTPException(400, {'code':'invalid_cursor','message':'Cursor is invalid'})

    def _atomic_json(self, path, value):
        temporary = self.directory / ('.cache-' + secrets.token_urlsafe(12) + '.tmp')
        try:
            with temporary.open('x', encoding='utf-8') as output:
                os.chmod(temporary, 0o600)
                json.dump(value, output, separators=(',', ':'))
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)

    @contextmanager
    def _index(self):
        # flock serialises separate processes; the thread lock also serialises
        # concurrent requests using this store instance. No network I/O occurs
        # while either lock is held.
        with self._thread_lock, (self.directory / '.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                path = self.directory / '.index.json'
                index = json.loads(path.read_text()) if path.exists() else {'sequence':0,'snapshots':{}}
                now = time.monotonic()
                for snapshot_id, meta in list(index['snapshots'].items()):
                    if meta['expires_at'] <= now:
                        index['snapshots'].pop(snapshot_id)
                        (self.directory / (snapshot_id + '.json')).unlink(missing_ok=True)
                # A worker killed between its data/index writes can leave an
                # orphan. Reclaim those files without growing the cache on retry.
                for file in self.directory.glob('*.json'):
                    if file.name != '.index.json' and file.stem not in index['snapshots']:
                        file.unlink(missing_ok=True)
                for file in self.directory.glob('.cache-*.tmp'):
                    file.unlink(missing_ok=True)
                yield index, now
                self._atomic_json(path, index)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def create(self, entries, principal, grants_fingerprint):
        if len(entries) > self.row_max:
            raise HTTPException(503, {'code':'read_snapshot_too_large',
                'message':'The result is too large for stable pagination'})
        # Explicit datetime tags preserve the existing fixed-precision cursor
        # comparator across processes; plain JSON strings are not datetimes.
        encoded = [[identifier, [
            ['datetime', key.isoformat()] if isinstance(key, datetime) else ['string', key]
            for key in ordering], revision] for identifier, ordering, revision in entries]
        snapshot_id = secrets.token_urlsafe(18)
        with self._index() as (index, now):
            self._atomic_json(self.directory / (snapshot_id + '.json'), encoded)
            index['sequence'] += 1
            index['snapshots'][snapshot_id] = {'expires_at':now + self.ttl_seconds,
                'sequence':index['sequence'],'principal':principal,'grants':grants_fingerprint}
            while len(index['snapshots']) > self.count_max:
                oldest = min(index['snapshots'], key=lambda key:index['snapshots'][key]['sequence'])
                index['snapshots'].pop(oldest)
                (self.directory / (oldest + '.json')).unlink(missing_ok=True)
        return snapshot_id

    def get(self, snapshot_id, principal, grants_fingerprint):
        if not isinstance(snapshot_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{24}', snapshot_id):
            self._invalid()
        with self._index() as (index, _now):
            meta = index['snapshots'].get(snapshot_id)
            if meta is None or meta['principal'] != principal or meta['grants'] != grants_fingerprint:
                self._invalid()
            try:
                values = json.loads((self.directory / (snapshot_id + '.json')).read_text())
                return tuple((identifier, tuple(datetime.fromisoformat(value) if kind=='datetime' else value
                    for kind, value in ordering), revision) for identifier, ordering, revision in values)
            except (OSError, ValueError, TypeError):
                self._invalid()
