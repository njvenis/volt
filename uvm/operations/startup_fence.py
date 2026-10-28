"""Verify the host-signed context that permits recovery-control startup."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
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
    if (not isinstance(value, dict) or set(value) != expected
            or type(value["schema_version"]) is not int or value["schema_version"] != 1):
        raise ValueError("startup token shape is invalid")
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
    return value


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
        print(json.dumps({"verified": True, "deployment_id": token["deployment_id"],
            "recovery_epoch": token["recovery_epoch"]}, separators=(",", ":")))
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        print("G7_RECOVERY_ERROR startup token rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
