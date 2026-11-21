from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from uvm.installer import offline_backup as backup

ROOT = Path(__file__).resolve().parents[2]


class OfflineBackupTests(unittest.TestCase):
    def tree(self, root):
        root.chmod(0o700)
        (root / 'a').mkdir(mode=0o750)
        (root / 'a/z').write_bytes(b'content')
        (root / 'a/z').chmod(0o600)
        (root / 'a.txt').write_text('sorting boundary')
        (root / 'PG_VERSION').write_text('17\n')
        (root / 'alias').symlink_to('a/z')

    def test_numeric_tar_matches_existing_cold_inventory_including_sorting_and_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, destination = Path(tmp) / 'source', Path(tmp) / 'backup'
            source.mkdir(); destination.mkdir(mode=0o700); self.tree(source)
            spec = importlib.util.spec_from_file_location('offline_inventory_setup', ROOT / 'deploy/compose/setup.py')
            setup = importlib.util.module_from_spec(spec); spec.loader.exec_module(setup)
            script = setup.INVENTORY_SCRIPT.replace("Path('/restore')", f'Path({str(source)!r})')
            legacy = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, check=True)
            expected = json.loads(legacy.stdout)
            self.assertEqual(backup.inventory(source), expected)
            with patch.object(backup, 'SOURCE', source), patch.object(backup, 'DESTINATION', destination):
                backup.capture('postgres')
            archive = destination / 'postgres.tar'
            self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
            self.assertEqual(archive.stat().st_uid, destination.stat().st_uid)
            self.assertEqual(backup.archive_inventory(archive), expected)

    def test_new_private_archive_never_overwrites_existing_file_or_link(self):
        for linked in (False, True):
            with self.subTest(linked=linked), tempfile.TemporaryDirectory() as tmp:
                source, destination = Path(tmp) / 'source', Path(tmp) / 'backup'
                source.mkdir(); destination.mkdir(mode=0o700); self.tree(source)
                original = destination / 'original'; original.write_bytes(b'preserved')
                target = destination / 'postgres.tar'
                target.symlink_to(original) if linked else target.write_bytes(b'preserved')
                with patch.object(backup, 'SOURCE', source), patch.object(backup, 'DESTINATION', destination):
                    with self.assertRaises(FileExistsError):
                        backup.capture('postgres')
                self.assertEqual(original.read_bytes(), b'preserved')
                self.assertEqual(target.read_bytes(), b'preserved')

    def test_source_special_files_and_inventory_bounds_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.tree(root)
            os.mkfifo(root / 'fifo', 0o600)
            with self.assertRaisesRegex(ValueError, 'special file'):
                backup.inventory(root)
            (root / 'fifo').unlink()
            with patch.object(backup, 'MAX_ENTRIES', 2):
                with self.assertRaisesRegex(ValueError, 'entry bound'):
                    backup.inventory(root)

    def test_archive_traversal_hardlinks_escaping_links_and_link_parents_are_denied(self):
        cases = ('traversal', 'hardlink', 'escaping-link', 'link-parent', 'oversize-pax')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'bad.tar'
                with tarfile.open(path, 'w') as archive:
                    root = tarfile.TarInfo('.'); root.type = tarfile.DIRTYPE; root.mode = 0o700
                    archive.addfile(root)
                    member = tarfile.TarInfo('../escape' if case == 'traversal' else 'alias')
                    if case == 'hardlink':
                        member.type = tarfile.LNKTYPE; member.linkname = 'other'
                    elif case in ('escaping-link', 'link-parent'):
                        member.type = tarfile.SYMTYPE; member.linkname = '../outside' if case == 'escaping-link' else 'inside'
                    elif case == 'oversize-pax':
                        member.type = tarfile.XHDTYPE; member.size = 65537
                    archive.addfile(member, io.BytesIO(b'\x00' * member.size))
                    if case == 'link-parent':
                        child = tarfile.TarInfo('alias/file'); archive.addfile(child)
                with self.assertRaises(ValueError):
                    backup.archive_inventory(path)
