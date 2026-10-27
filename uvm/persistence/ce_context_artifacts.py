"""Content-addressed local storage for immutable DefectDojo context bytes.

This is a crash-safe local byte store, not a tamper-proof audit archive.  The
root is an existing, service-owned absolute directory configured by the
caller.  References contain only a SHA-256 digest; no caller-supplied path
component is used to address the filesystem.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
from pathlib import Path


_REFERENCE = re.compile(r"\Ace-context-sha256:([0-9a-f]{64})\Z")
_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class CEContextArtifactError(Exception):
    """Base class for fail-closed local artifact store errors."""


class InvalidReference(CEContextArtifactError, ValueError):
    """The reference or expected digest is not a valid SHA-256 value."""


class UnsafeStoreRoot(CEContextArtifactError):
    """The configured root or a derived path component is unsafe."""


class ArtifactNotFound(CEContextArtifactError, FileNotFoundError):
    """The requested artifact does not exist."""


class ArtifactCorrupt(CEContextArtifactError):
    """An existing artifact is not a regular, correctly protected byte file."""


class ArtifactConflict(CEContextArtifactError):
    """An existing digest path contains bytes for a different digest."""


class ArtifactIOError(CEContextArtifactError):
    """A storage operation could not complete safely."""


def _mode_is(mode: int, expected: int) -> bool:
    return stat.S_ISDIR(mode) and (mode & 0o7777) == expected


def _check_digest(value: str) -> str:
    if not isinstance(value, str):
        raise InvalidReference("digest must be a string")
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise InvalidReference("digest must be 64 lowercase hexadecimal characters")
    return value


class CEContextArtifactStore:
    """Store and retrieve exact bytes under ``sha256/<prefix>/<digest>``."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        path = os.fspath(root)
        if not os.path.isabs(path):
            raise UnsafeStoreRoot("artifact root must be an absolute path")
        if not _NOFOLLOW:
            raise UnsafeStoreRoot("artifact root requires no-follow filesystem support")
        self._reject_source_checkout_path(path)
        try:
            self._root_fd = self._open_root_path(path)
        except OSError as exc:
            raise UnsafeStoreRoot("could not open artifact root safely") from exc
        try:
            opened = os.fstat(self._root_fd)
            if not _mode_is(opened.st_mode, _DIRECTORY_MODE) or opened.st_uid != os.geteuid():
                raise UnsafeStoreRoot("artifact root must be an euid-owned 0700 directory")
        except Exception:
            os.close(self._root_fd)
            raise

    @staticmethod
    def _source_checkout() -> Path | None:
        module_path = Path(__file__).resolve()
        for candidate in (module_path, *module_path.parents):
            if (candidate / ".git").is_dir() or (candidate / ".git").is_file():
                return candidate
        return None

    @classmethod
    def _reject_source_checkout_path(cls, path: str) -> None:
        checkout = cls._source_checkout()
        if checkout is None:
            return
        try:
            inside = os.path.commonpath((os.path.realpath(path), os.fspath(checkout))) == os.fspath(checkout)
        except ValueError:
            inside = False
        if inside:
            raise UnsafeStoreRoot("artifact root must be outside the source checkout")

    @staticmethod
    def _open_root_path(path: str) -> int:
        current = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW)
        try:
            for component in Path(path).parts[1:]:
                if not component:
                    continue
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW, dir_fd=current)
                os.close(current)
                current = next_fd
            return current
        except Exception:
            os.close(current)
            raise

    def close(self) -> None:
        if getattr(self, "_root_fd", -1) >= 0:
            os.close(self._root_fd)
            self._root_fd = -1

    def __enter__(self) -> "CEContextArtifactStore":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    @staticmethod
    def reference_for_digest(digest: str) -> str:
        return f"ce-context-sha256:{_check_digest(digest)}"

    @staticmethod
    def _digest_from_reference(reference: str) -> str:
        if not isinstance(reference, str):
            raise InvalidReference("reference must be a string")
        match = _REFERENCE.fullmatch(reference)
        if match is None:
            raise InvalidReference("invalid CE context artifact reference")
        return match.group(1)

    def _open_dir(self, parent_fd: int, name: str, *, create: bool) -> int:
        try:
            if create:
                try:
                    os.mkdir(name, _DIRECTORY_MODE, dir_fd=parent_fd)
                except FileExistsError:
                    pass
                try:
                    os.fsync(parent_fd)
                except OSError as exc:
                    raise ArtifactIOError("artifact directory durability sync failed") from exc
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW, dir_fd=parent_fd)
        except ArtifactIOError:
            raise
        except OSError as exc:
            raise UnsafeStoreRoot(f"unsafe artifact directory: {name}") from exc
        try:
            if not _mode_is(os.fstat(fd).st_mode, _DIRECTORY_MODE):
                raise UnsafeStoreRoot(f"artifact directory has unsafe mode: {name}")
            return fd
        except Exception:
            os.close(fd)
            raise

    def _unlink_temporary(self, directory_fd: int, name: str) -> None:
        try:
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise ArtifactIOError(
                "temporary artifact cleanup failed; retained bytes require recovery"
            ) from exc

    @staticmethod
    def _validate_installed(directory_fd: int, digest: str, data: bytes, temporary_fd: int) -> None:
        try:
            final_fd = os.open(digest, os.O_RDONLY | _NOFOLLOW, dir_fd=directory_fd)
        except OSError as exc:
            raise ArtifactIOError("installed artifact cannot be opened safely") from exc
        try:
            temporary = os.fstat(temporary_fd)
            final = os.fstat(final_fd)
            if (
                not stat.S_ISREG(final.st_mode)
                or (final.st_mode & 0o7777) != _FILE_MODE
                or (final.st_dev, final.st_ino) != (temporary.st_dev, temporary.st_ino)
            ):
                raise ArtifactIOError("installed artifact identity or mode could not be verified")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(final_fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            installed = b"".join(chunks)
            if len(installed) != len(data) or hashlib.sha256(installed).hexdigest() != digest:
                raise ArtifactIOError("installed artifact digest could not be verified")
        except ArtifactIOError:
            raise
        except OSError as exc:
            raise ArtifactIOError("installed artifact verification failed") from exc
        finally:
            os.close(final_fd)

    def _digest_dir(self, digest: str, *, create: bool) -> int:
        sha_fd = self._open_dir(self._root_fd, "sha256", create=create)
        try:
            return self._open_dir(sha_fd, digest[:2], create=create)
        finally:
            os.close(sha_fd)

    @staticmethod
    def _read_existing(directory_fd: int, digest: str) -> bytes:
        try:
            fd = os.open(digest, os.O_RDONLY | _NOFOLLOW, dir_fd=directory_fd)
        except FileNotFoundError as exc:
            raise ArtifactNotFound("artifact does not exist") from exc
        except OSError as exc:
            raise ArtifactCorrupt("artifact cannot be opened safely") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or (info.st_mode & 0o7777) != _FILE_MODE:
                raise ArtifactCorrupt("artifact is not a regular 0600 file")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            result = b"".join(chunks)
            after = os.fstat(fd)
            if after.st_size != info.st_size or hashlib.sha256(result).hexdigest() != digest:
                raise ArtifactCorrupt("artifact bytes do not match its digest")
            return result
        except ArtifactCorrupt:
            raise
        except OSError as exc:
            raise ArtifactIOError("artifact read failed") from exc
        finally:
            os.close(fd)

    def put(self, data: bytes) -> tuple[str, str]:
        if not isinstance(data, bytes):
            raise TypeError("artifact data must be bytes")
        digest = hashlib.sha256(data).hexdigest()
        reference = self.reference_for_digest(digest)
        directory_fd = self._digest_dir(digest, create=True)
        temporary_name = f".tmp-{secrets.token_hex(16)}"
        temp_fd = -1
        installed = False
        try:
            try:
                temp_fd = os.open(
                    temporary_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                    _FILE_MODE,
                    dir_fd=directory_fd,
                )
                os.fchmod(temp_fd, _FILE_MODE)
                offset = 0
                while offset < len(data):
                    offset += os.write(temp_fd, data[offset:])
                os.fsync(temp_fd)
                try:
                    os.link(
                        temporary_name,
                        digest,
                        src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    installed = True
                    self._validate_installed(directory_fd, digest, data, temp_fd)
                    self._unlink_temporary(directory_fd, temporary_name)
                    os.fsync(directory_fd)
                    return reference, digest
                except FileExistsError:
                    existing = self._read_existing(directory_fd, digest)
                    if existing != data:
                        raise ArtifactConflict("digest path contains different bytes")
                    self._unlink_temporary(directory_fd, temporary_name)
                    os.fsync(directory_fd)
                    return reference, digest
            except ArtifactConflict:
                raise
            except (OSError, ValueError) as exc:
                raise ArtifactIOError("artifact write failed") from exc
        finally:
            if temp_fd >= 0:
                os.close(temp_fd)
            if not installed:
                try:
                    os.unlink(temporary_name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
            os.close(directory_fd)

    def get(self, reference: str, expected_digest: str) -> bytes:
        digest = self._digest_from_reference(reference)
        if _check_digest(expected_digest) != digest:
            raise InvalidReference("expected digest does not match reference")
        directory_fd = self._digest_dir(digest, create=False)
        try:
            return self._read_existing(directory_fd, digest)
        finally:
            os.close(directory_fd)
