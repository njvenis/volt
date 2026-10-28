"""Verify the host-signed context that permits recovery-control startup."""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone

from uvm.operations.backup_host import parse_utc, verify_signature


def verify_startup_fence(token_path: str, public_key_path: str, *, deployment_id: str,
        image_digest: str, volume_ids: dict[str, str], archive_digest: str,
        recovery_epoch: int, connector_recovery_id: str, key_id: str) -> dict:
    value = json.loads(Path(token_path).read_text(encoding="utf-8"),
        object_pairs_hook=_unique_pairs, parse_float=_reject_float,
        parse_constant=_reject_constant)
    expected = {"schema_version", "deployment_id", "target_image_digest", "volume_ids",
        "archive_digest", "recovery_epoch", "connector_recovery_id", "issued_at", "signature"}
    fields = set(value) if isinstance(value, dict) else set()
    if (not isinstance(value, dict) or fields not in (expected, expected | {"compatibility_admission"})
            or type(value["schema_version"]) is not int or value["schema_version"] != 1):
        raise ValueError("startup token shape is invalid")
    if (set(volume_ids) != {"postgres_cluster", "ce_media", "uvm_state"} or
            any(not isinstance(item, str) or not item for item in volume_ids.values()) or
            len(set(volume_ids.values())) != 3 or
            str(uuid.UUID(connector_recovery_id)) != connector_recovery_id):
        raise ValueError("startup volume or connector identities are invalid")
    issued = parse_utc(value["issued_at"])
    now = datetime.now(timezone.utc)
    max_age = int(os.getenv("UVM_G7_STARTUP_TOKEN_MAX_AGE_SECONDS", "300"))
    max_future_skew = int(os.getenv("UVM_G7_INITIAL_MAXIMUM_FUTURE_SKEW_SECONDS", "30"))
    if max_age < 1 or max_future_skew < 0 or issued < now - timedelta(seconds=max_age) \
            or issued > now + timedelta(seconds=max_future_skew):
        raise ValueError("startup token is stale or future dated")
    verify_signature(value, public_key_path, key_id)
    if (value["deployment_id"] != deployment_id
            or value["target_image_digest"] != image_digest
            or value["volume_ids"] != volume_ids
            or value["archive_digest"] != archive_digest
            or type(value["recovery_epoch"]) is not int
            or value["recovery_epoch"] != recovery_epoch
            or value["connector_recovery_id"] != connector_recovery_id):
        raise ValueError("startup token does not bind this restore target")
    admission = value.get("compatibility_admission")
    if admission is not None:
        required = {"admission_id", "recovery_epoch", "source_image_digest", "source_package_manifest_digest",
            "target_image_digest", "target_package_manifest_digest", "archive_digest",
            "from_schema", "to_schema", "volume_ids"}
        if (not isinstance(admission, dict) or set(admission) != required
                or str(uuid.UUID(admission["admission_id"])) != admission["admission_id"]
                or type(admission["recovery_epoch"]) is not int
                or admission["recovery_epoch"] != recovery_epoch
                or admission["target_image_digest"] != image_digest
                or admission["archive_digest"] != archive_digest
                or admission["volume_ids"] != volume_ids
                or admission["from_schema"] != "0058" or admission["to_schema"] != "0059"
                or admission["target_package_manifest_digest"] != _runtime_package_digest()):
            raise ValueError("startup token compatibility admission is invalid")
        for field in ("source_image_digest", "source_package_manifest_digest",
                "target_image_digest", "target_package_manifest_digest", "archive_digest"):
            if not isinstance(admission[field], str) or not re.fullmatch(
                    r"sha256:[0-9a-f]{64}", admission[field]):
                raise ValueError("startup token compatibility digest is invalid")
    if os.getenv("UVM_G7_SCHEMA_MODE", "normal") == "upgrade-verification" and admission is None:
        raise ValueError("upgrade verification lacks a compatibility admission")
    return value


def _runtime_package_digest() -> str:
    root = Path("/opt/uvm/app")
    digest = hashlib.sha256()
    for name in ("pyproject.toml", "uv.lock"):
        digest.update(name.encode() + b"\0" + (root / name).read_bytes() + b"\0")
    return "sha256:" + digest.hexdigest()


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate startup token member")
        result[key] = value
    return result


def _reject_float(_value):
    raise ValueError("floating point startup token value")


def _reject_constant(_value):
    raise ValueError("non-finite startup token value")


def startup_admitted(engine, token: dict, *, released: bool = False) -> bool:
    """Require the resync and restored event for this exact signed startup."""
    import sqlalchemy as sa
    from uvm.persistence.backup_settings_schema import g7_backup_host_records, g7_backup_state
    with engine.connect() as connection:
        state = connection.execute(sa.select(g7_backup_state).where(
            g7_backup_state.c.deployment_id == token["deployment_id"])).mappings().first()
        if (not state or state["restore_state"] not in ({"released"} if released else {"restored", "verified", "released"}) or
                state["recovery_epoch"] != token["recovery_epoch"]):
            return False
        records = connection.execute(sa.select(g7_backup_host_records).where(
            g7_backup_host_records.c.deployment_id == token["deployment_id"],
            g7_backup_host_records.c.recovery_epoch == token["recovery_epoch"])).mappings().all()
        resync = any(record["record_kind"] == "resync" and
            record["document"].get("checkpoint_epoch_floor") == token["recovery_epoch"] and
            parse_utc(record["document"]["issued_at"]) >= parse_utc(token["issued_at"])
            for record in records)
        restored = next((record["document"] for record in records if
            record["record_kind"] == "recovery" and
            record["document"].get("event_type") == "volumes_restored"), None)
        return bool(resync and restored and
            restored["connector_recovery_id"] == token["connector_recovery_id"] and
            restored["manifest_digest"] == token["archive_digest"] and
            restored["target_image_digest"] == token["target_image_digest"] and
            restored["new_volume_ids"] == token["volume_ids"])


def host_release_authorized(token: dict, path="/run/uvm-g7/host-release") -> bool:
    try:
        marker = Path(path)
        stat = marker.stat()
        return stat.st_uid == 0 and stat.st_mode & 0o022 == 0 and json.loads(marker.read_text()) == token
    except (OSError, ValueError):
        return False


def main() -> int:
    try:
        raw_volumes = json.loads(os.environ["UVM_G7_RECOVERY_VOLUME_IDS"])
        if not isinstance(raw_volumes, dict) or set(raw_volumes) != {
                "postgres_cluster", "ce_media", "uvm_state"}:
            raise ValueError("volume identity set is invalid")
        token = verify_startup_fence(
            os.environ["UVM_G7_STARTUP_FENCE_TOKEN"],
            os.environ["UVM_G7_HOST_PUBLIC_KEY_FILE"],
            deployment_id=os.environ["UVM_G7_DEPLOYMENT_ID"],
            image_digest=os.environ["UVM_G7_TARGET_IMAGE_DIGEST"],
            volume_ids=raw_volumes,
            archive_digest=os.environ["UVM_G7_ARCHIVE_DIGEST"],
            recovery_epoch=int(os.environ["UVM_G7_RECOVERY_EPOCH"]),
            connector_recovery_id=os.environ["UVM_G7_CONNECTOR_RECOVERY_ID"],
            key_id=os.environ["UVM_G7_HOST_KEY_ID"])
        if any(flag in sys.argv for flag in ("--check-admission", "--check-release", "--check-host-release", "--authorize-host-release")):
            import sqlalchemy as sa
            if not startup_admitted(sa.create_engine(os.environ["UVM_DB_URL"]), token,
                    released=any(flag in sys.argv for flag in ("--check-release", "--check-host-release", "--authorize-host-release"))):
                return 1
        if "--check-schema-admission" in sys.argv and token.get("compatibility_admission") is None:
            return 1
        if "--authorize-host-release" in sys.argv:
            from uvm.operations.backup_host import canonical_json
            marker = Path("/run/uvm-g7/host-release")
            temporary = marker.with_suffix(".tmp")
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(canonical_json(token)); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, marker)
            directory = os.open(marker.parent, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
        if "--check-host-release" in sys.argv and not host_release_authorized(token):
            return 1
        print(json.dumps({"verified": True, "deployment_id": token["deployment_id"],
            "recovery_epoch": token["recovery_epoch"]}, separators=(",", ":")))
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        print("G7_RECOVERY_ERROR startup token rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
