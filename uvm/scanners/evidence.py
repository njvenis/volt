"""Private, bounded retention for exact successful Qualys XML pages."""
from __future__ import annotations

import hashlib
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path

from uvm.scanners.qualys_vm import MAX_PAGE_BYTES


@dataclass(frozen=True)
class EvidenceReceipt:
    ref: str
    sha256: str
    size: int


class PrivateEvidenceStore:
    """Writes opaque page refs using directory-relative no-follow file operations.

    The directory is deployment-owned and must already exist with private
    permissions. The scanner adapter never returns the retained bytes through
    an API DTO.
    """
    def __init__(self, directory: str | os.PathLike[str], *,
                 max_page_bytes: int = MAX_PAGE_BYTES,
                 max_total_bytes: int = 50 * 1024 * 1024):
        self.directory = Path(directory)
        self.max_page_bytes, self.max_total_bytes = max_page_bytes, max_total_bytes
        if max_page_bytes < 1 or max_total_bytes < max_page_bytes:
            raise ValueError("invalid evidence limits")

    def _directory_fd(self) -> int:
        if not self.directory.is_absolute() or any(part in {".", ".."}
                for part in self.directory.parts):
            raise ValueError("evidence_directory_must_be_normal_absolute_path")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open("/", flags)
        try:
            for part in self.directory.parts[1:]:
                child_fd = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child_fd
        except BaseException:
            os.close(fd)
            raise
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
            os.close(fd)
            raise PermissionError("evidence_directory_not_private")
        return fd

    def write(self, data: bytes, *, operation_bytes: int = 0) -> EvidenceReceipt:
        if not isinstance(data, bytes) or len(data) > self.max_page_bytes:
            raise ValueError("evidence_page_limit")
        if operation_bytes < 0 or operation_bytes + len(data) > self.max_total_bytes:
            raise ValueError("evidence_operation_limit")
        directory_fd = self._directory_fd()
        token = uuid.uuid4().hex
        temp_name, final_name = "." + token + ".tmp", token + ".xml"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = None
        try:
            fd = os.open(temp_name, flags, 0o600, dir_fd=directory_fd)
            with os.fdopen(fd, "wb", closefd=True) as stream:
                fd = None
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temp_name, final_name, src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd, follow_symlinks=False)
            os.unlink(temp_name, dir_fd=directory_fd)
            os.fsync(directory_fd)
            return EvidenceReceipt("qualys-page-v1/" + token,
                hashlib.sha256(data).hexdigest(), len(data))
        finally:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(temp_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            os.close(directory_fd)

    def read(self, ref: str) -> bytes:
        prefix, _, token = ref.partition("/")
        if prefix != "qualys-page-v1" or len(token) != 32 or any(
                char not in "0123456789abcdef" for char in token):
            raise ValueError("invalid_evidence_ref")
        directory_fd = self._directory_fd()
        fd = None
        try:
            fd = os.open(token + ".xml", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                         dir_fd=directory_fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > self.max_page_bytes:
                raise ValueError("invalid_evidence_file")
            with os.fdopen(fd, "rb", closefd=True) as stream:
                fd = None
                return stream.read(self.max_page_bytes + 1)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(directory_fd)
