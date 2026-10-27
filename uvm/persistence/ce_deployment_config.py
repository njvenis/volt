"""Safe, explicit local snapshots of caller-owned DefectDojo configuration.

This loader is deliberately not a runtime discovery mechanism.  It reads one
operator-selected file, validates only the allowlisted configuration fields,
and returns the bytes that can later be handed to the local context artifact
store.  The result must not be described as live CE identity or API evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from uvm.engine.context import ConfiguredCEDeploymentV1


MAX_CONFIG_BYTES = 64 * 1024
_FILE_MODE = 0o600
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_CONFIG_KEYS = frozenset({"schema_version", "deployment_key", "ce_base_url", "ce_release"})
LOCAL_OPERATOR_CONFIGURATION_SNAPSHOT = "recorded local operator configuration snapshot"


class CEDeploymentConfigError(ValueError):
    """Base class for rejected or unreadable local deployment configuration."""


class UnsafeCEDeploymentConfig(CEDeploymentConfigError):
    """The selected path does not meet the local file safety policy."""


class InvalidCEDeploymentConfig(CEDeploymentConfigError):
    """The selected file is not the deterministic V1 JSON document."""


@dataclass(frozen=True)
class LocalCEDeploymentConfigSnapshotV1:
    """An immutable operator configuration snapshot, not live CE evidence."""

    configured: ConfiguredCEDeploymentV1
    config_bytes: bytes
    config_sha256: str
    provenance: str = LOCAL_OPERATOR_CONFIGURATION_SNAPSHOT

    def __post_init__(self) -> None:
        if self.provenance != LOCAL_OPERATOR_CONFIGURATION_SNAPSHOT:
            raise ValueError("unsupported configuration snapshot provenance")
        payload = bytes(self.config_bytes)
        digest = hashlib.sha256(payload).hexdigest()
        if digest != self.config_sha256:
            raise ValueError("configuration bytes and digest do not match")
        object.__setattr__(self, "config_bytes", payload)


CEDeploymentConfigSnapshotV1 = LocalCEDeploymentConfigSnapshotV1


def _source_checkout() -> Path | None:
    module_path = Path(__file__).resolve()
    for candidate in (module_path, *module_path.parents):
        if (candidate / ".git").is_dir() or (candidate / ".git").is_file():
            return candidate
    return None


def _reject_checkout_path(path: str) -> None:
    checkout = _source_checkout()
    if checkout is None:
        return
    try:
        if os.path.commonpath((os.path.realpath(path), os.fspath(checkout))) == os.fspath(checkout):
            raise UnsafeCEDeploymentConfig("configuration file must be outside the source checkout")
    except ValueError:
        return


def _open_file_without_symlinks(path: str) -> int:
    if not _NOFOLLOW:
        raise UnsafeCEDeploymentConfig("configuration loading requires no-follow filesystem support")
    parts = Path(path).parts
    if not parts or parts[0] != os.sep or any(part in {"", ".", ".."} for part in parts[1:]):
        raise UnsafeCEDeploymentConfig("configuration path must be a normal absolute path")
    current = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW)
    try:
        for component in parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW, dir_fd=current)
            os.close(current)
            current = next_fd
        return os.open(parts[-1], os.O_RDONLY | _NOFOLLOW | _NONBLOCK, dir_fd=current)
    except OSError as exc:
        raise UnsafeCEDeploymentConfig("configuration path contains an unsafe or missing component") from exc
    finally:
        os.close(current)


def _read_snapshot(path: str) -> bytes:
    try:
        fd = _open_file_without_symlinks(path)
    except CEDeploymentConfigError:
        raise
    except OSError as exc:
        raise UnsafeCEDeploymentConfig("configuration path cannot be opened safely") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != _FILE_MODE:
            raise UnsafeCEDeploymentConfig("configuration must be an euid-owned regular 0600 file")
        if before.st_uid != os.geteuid():
            raise UnsafeCEDeploymentConfig("configuration must be owned by the effective UID")
        if before.st_size > MAX_CONFIG_BYTES:
            raise UnsafeCEDeploymentConfig("configuration exceeds the size limit")
        # These descriptor checks are best-effort change detection, not an
        # immutability or same-UID anti-tamper guarantee. The bytes returned
        # below are exactly the bytes read from this descriptor.
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                raise UnsafeCEDeploymentConfig("configuration changed while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
        ):
            raise UnsafeCEDeploymentConfig("configuration changed while being read")
        return b"".join(chunks)
    except OSError as exc:
        raise UnsafeCEDeploymentConfig("configuration could not be read safely") from exc
    finally:
        os.close(fd)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidCEDeploymentConfig("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> Any:
    raise InvalidCEDeploymentConfig(f"non-finite JSON number: {value}")


def _parse_config(payload: bytes) -> ConfiguredCEDeploymentV1:
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, InvalidCEDeploymentConfig) as exc:
        raise InvalidCEDeploymentConfig("configuration must be valid UTF-8 JSON") from exc
    if not isinstance(document, dict) or set(document) != _CONFIG_KEYS:
        raise InvalidCEDeploymentConfig("configuration contains unknown or missing fields")
    if any(isinstance(value, (dict, list)) for value in document.values()):
        raise InvalidCEDeploymentConfig("configuration fields have invalid types")
    if not isinstance(document["schema_version"], int) or isinstance(document["schema_version"], bool):
        raise InvalidCEDeploymentConfig("schema_version must be an integer")
    for key in ("deployment_key", "ce_base_url", "ce_release"):
        value = document[key]
        if not isinstance(value, str) or any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise InvalidCEDeploymentConfig(f"{key} must be a valid Unicode string")
    try:
        return ConfiguredCEDeploymentV1(**document)
    except (TypeError, ValueError) as exc:
        raise InvalidCEDeploymentConfig("configuration does not satisfy ConfiguredCEDeploymentV1") from exc


def load_ce_deployment_config(path: str | os.PathLike[str]) -> LocalCEDeploymentConfigSnapshotV1:
    """Load one explicit operator-owned configuration file safely."""
    raw_path = os.fspath(path)
    if not os.path.isabs(raw_path):
        raise UnsafeCEDeploymentConfig("configuration path must be absolute")
    _reject_checkout_path(raw_path)
    payload = _read_snapshot(raw_path)
    configured = _parse_config(payload)
    canonical = json.dumps(
        {
            "schema_version": configured.schema_version,
            "deployment_key": configured.deployment_key,
            "ce_base_url": configured.ce_base_url,
            "ce_release": configured.ce_release,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return LocalCEDeploymentConfigSnapshotV1(
        configured=configured,
        config_bytes=canonical,
        config_sha256=hashlib.sha256(canonical).hexdigest(),
    )


load_local_ce_deployment_config = load_ce_deployment_config
