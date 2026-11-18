"""Host custody preparation and approval signing for the explicit local profile.

This module is invoked only in an admitted, networkless ephemeral helper
container. It has no API service or Docker socket integration.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import uuid

PROFILE = "volt_local_recovery_v1"
UTC = timezone.utc
MAX_REQUEST = 16 * 1024
PATH_POLICY = {
    "api_config": "local-recovery.json",
    "runtime_directory": "secrets/local-recovery-runtime",
    "authority_directory": "secrets/local-recovery-authority",
    "fence_directory": "secrets/local-restore-fence",
    "journal": "instance.json",
}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _no_float(value):
    raise ValueError("noninteger JSON number")


def _read_request(stream) -> dict:
    raw = stream.buffer.read(MAX_REQUEST + 1)
    if len(raw) > MAX_REQUEST:
        raise ValueError("request is too large")
    value = json.loads(raw, object_pairs_hook=_pairs, parse_float=_no_float,
                       parse_constant=_no_float)
    expected = {"schema_version", "profile", "installation_id", "journal_id", "path_policy"}
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("request schema is invalid")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["profile"] != PROFILE
            or not isinstance(value["installation_id"], str)
            or not isinstance(value["journal_id"], str)
            or str(uuid.UUID(value["installation_id"])) != value["installation_id"]
            or str(uuid.UUID(value["journal_id"])) != value["journal_id"]
            or value["path_policy"] != PATH_POLICY):
        raise ValueError("request identity or path policy is invalid")
    return value


def _request_for_instance(root: Path) -> dict:
    info = root.lstat()
    if (root.is_symlink() or not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid()):
        raise ValueError("instance root is unsafe")
    metadata = json.loads(_private_file(root / "instance.json"), object_pairs_hook=_pairs,
                          parse_float=_no_float, parse_constant=_no_float)
    if (not isinstance(metadata, dict) or metadata.get("mode") != "local"
            or type(metadata.get("established")) is not bool
            or not isinstance(metadata.get("installation_id"), str)
            or not isinstance(metadata.get("local_recovery_journal_id"), str)):
        raise ValueError("local installation journal is incomplete")
    installation_id = metadata["installation_id"]
    journal_id = metadata["local_recovery_journal_id"]
    if (str(uuid.UUID(installation_id)) != installation_id
            or str(uuid.UUID(journal_id)) != journal_id):
        raise ValueError("local installation journal identity is invalid")
    local_config = json.loads(_private_file(root / "local-auth.json"),
        object_pairs_hook=_pairs, parse_float=_no_float, parse_constant=_no_float)
    if hashlib.sha256(_private_file(root / "local-auth.json")).hexdigest() != metadata.get("local_auth_config_sha256"):
        raise ValueError("local authentication configuration changed after setup")
    local_key = _private_file(root / "secrets/local-auth-key")
    source = local_config.get("secret_source") if isinstance(local_config, dict) else None
    if (not isinstance(local_config, dict) or local_config.get("schema_version") != 1
            or local_config.get("installation_id") != installation_id
            or not isinstance(source, dict)
            or source.get("kind") != "encrypted_local_v1"
            or source.get("key_path") != "/run/uvm-connector/local-key"
            or not isinstance(source.get("secret_source_id"), str)
            or str(uuid.UUID(source["secret_source_id"])) != source["secret_source_id"]
            or len(local_key) != 32):
        raise ValueError("local encrypted-secret source identity is invalid")
    return {"schema_version": 1, "profile": PROFILE,
        "installation_id": installation_id, "journal_id": journal_id,
        "path_policy": PATH_POLICY}


def _canonical(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _read_document(stream, *, limit: int = 64 * 1024) -> dict:
    raw = stream.buffer.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("approval request is too large")
    value = json.loads(raw, object_pairs_hook=_pairs, parse_float=_no_float,
                       parse_constant=_no_float)
    if not isinstance(value, dict):
        raise ValueError("approval request is not an object")
    return value


def _uuid(value: object) -> str:
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("approval request UUID is invalid")
    return value


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("approval timestamp is invalid")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("approval timestamp is invalid")
    if parsed.astimezone(UTC).isoformat().replace("+00:00", "Z") != value:
        raise ValueError("approval timestamp is not canonical")
    return parsed.astimezone(UTC)


def approve_document(request: dict, host_config: dict, operator_seed: bytes,
                     operator_public: bytes, issuer_public: bytes,
                     fence: dict, journal: dict) -> dict:
    """Validate the backend request against independent host custody and sign it."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    request_fields = {"schema_version", "profile", "operation", "installation_id",
        "operator_key_id", "operator_id", "journal_id", "restore_generation",
        "recovery_epoch_id", "target", "attestation", "attestation_sha256",
        "rationale", "evidence_ref"}
    if (set(request) != request_fields or type(request["schema_version"]) is not int
            or request["schema_version"] != 1 or request["profile"] != PROFILE
            or request["operation"] != "scanner_recovery_approval_request"):
        raise ValueError("approval request schema is invalid")
    target_fields = {"connector_id", "source_id", "source_tuple", "secret_id", "version_id",
                     "purpose", "configuration_revision", "display_name", "account_label"}
    target = request["target"]
    if (not isinstance(target, dict) or set(target) != target_fields
            or type(target["configuration_revision"]) is not int
            or target["configuration_revision"] < 1 or target["purpose"] != "qualys_vm_basic"
            or not isinstance(target["source_tuple"], dict)
            or set(target["source_tuple"]) != {"source_family", "source_account_id", "scope_key"}
            or target["source_tuple"]["source_family"] != "qualys"):
        raise ValueError("approval target schema is invalid")
    for key in ("connector_id", "source_id", "secret_id", "version_id"):
        _uuid(target[key])
    for key in ("source_account_id", "scope_key"):
        if not isinstance(target["source_tuple"][key], str) or not target["source_tuple"][key]:
            raise ValueError("approval source scope is invalid")
    if any(not isinstance(target[key], str) or not target[key].strip() or len(target[key]) > 2048
           for key in ("display_name", "account_label")):
        raise ValueError("approval source label is invalid")
    installation_id = _uuid(request["installation_id"])
    journal_id = _uuid(request["journal_id"])
    recovery_epoch_id = _uuid(request["recovery_epoch_id"])
    if (type(request["restore_generation"]) is not int or request["restore_generation"] < 1
            or not isinstance(request["rationale"], str) or not request["rationale"].strip()
            or len(request["rationale"]) > 2048
            or not isinstance(request["evidence_ref"], str) or not request["evidence_ref"].strip()
            or len(request["evidence_ref"]) > 2048):
        raise ValueError("approval custody or rationale is invalid")

    host_fields = {"schema_version", "profile", "installation_id", "operator_id",
        "operator_key_id", "operator_private_key_file", "operator_public_key_file",
        "issuer_key_id", "issuer_public_key_file", "restore_fence_file", "journal_file"}
    if (set(host_config) != host_fields or host_config["schema_version"] != 1
            or host_config["profile"] != PROFILE
            or host_config["operator_private_key_file"] != "/authority/operator.key"
            or host_config["operator_public_key_file"] != "/authority/operator.pub"
            or host_config["issuer_public_key_file"] != "/authority/issuer.pub"
            or host_config["restore_fence_file"] != "/authority/fence/fence.json"
            or host_config["journal_file"] != "/authority/instance.json"):
        raise ValueError("host authority configuration is invalid")
    operator_key_id = _uuid(host_config["operator_key_id"])
    issuer_key_id = _uuid(host_config["issuer_key_id"])
    operator_id = host_config["operator_id"]
    if (host_config["installation_id"] != installation_id
            or operator_id != f"local-host:{installation_id}"
            or request["operator_key_id"] != operator_key_id
            or request["operator_id"] != operator_id):
        raise ValueError("approval identity differs from host authority")
    custody = journal.get("local_recovery_custody") if isinstance(journal, dict) else None
    expected_tuple = {"schema_version": 1, "profile": PROFILE,
        "installation_id": installation_id, "journal_id": journal_id,
        "restore_generation": request["restore_generation"],
        "recovery_epoch_id": recovery_epoch_id}
    if (journal.get("mode") != "local" or journal.get("installation_id") != installation_id
            or journal.get("local_recovery_journal_id") != journal_id
            or custody != expected_tuple or fence != expected_tuple
            or request["restore_generation"] < 1):
        raise ValueError("approval request differs from the committed host restore fence")
    if len(operator_seed) != 32 or len(operator_public) != 32 or len(issuer_public) != 32:
        raise ValueError("host authority key length is invalid")
    derived_public = Ed25519PrivateKey.from_private_bytes(operator_seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    if derived_public != operator_public:
        raise ValueError("operator private and public keys disagree")

    attestation_fields = {"schema_version", "profile", "document_type", "attestation_id",
        "installation_id", "issuer_key_id", "connector_id", "source_id", "source_tuple",
        "secret_id", "version_id", "purpose", "recovery_epoch_id", "issued_at",
        "issued_after_epoch", "freshness_policy", "credential_commitment", "signature"}
    attestation = request["attestation"]
    if (not isinstance(attestation, dict) or set(attestation) != attestation_fields
            or type(attestation["schema_version"]) is not int or attestation["schema_version"] != 2
            or attestation["profile"] != PROFILE
            or attestation["document_type"] != "credential_attestation"
            or attestation["issuer_key_id"] != issuer_key_id
            or attestation["issued_after_epoch"] is not True
            or attestation["freshness_policy"] != "no_retained_password_reuse_v1"
            or not re.fullmatch(r"[0-9a-f]{64}", attestation.get("credential_commitment", ""))):
        raise ValueError("credential attestation schema is invalid")
    expected_attestation_context = {"installation_id": installation_id,
        "connector_id": target["connector_id"], "source_id": target["source_id"],
        "source_tuple": target["source_tuple"], "secret_id": target["secret_id"],
        "version_id": target["version_id"], "purpose": target["purpose"],
        "recovery_epoch_id": recovery_epoch_id}
    if any(attestation[key] != value for key, value in expected_attestation_context.items()):
        raise ValueError("credential attestation differs from the selected recovery target")
    _uuid(attestation["attestation_id"])
    issued = _timestamp(attestation["issued_at"])
    if issued > datetime.now(UTC):
        raise ValueError("credential attestation is from the future")
    signature = base64.b64decode(attestation["signature"], validate=True)
    if len(signature) != 64:
        raise ValueError("credential attestation signature is invalid")
    Ed25519PublicKey.from_public_bytes(issuer_public).verify(
        signature, _canonical({key: value for key, value in attestation.items() if key != "signature"}))
    attestation_digest = hashlib.sha256(_canonical(attestation)).hexdigest()
    if request["attestation_sha256"] != attestation_digest:
        raise ValueError("credential attestation digest is invalid")

    now = datetime.now(UTC)
    approval = {"schema_version": 2, "profile": PROFILE,
        "document_type": "operator_clearance", "approval_id": str(uuid.uuid4()),
        "installation_id": installation_id, "operator_key_id": operator_key_id,
        "operator_id": operator_id, "connector_id": target["connector_id"],
        "source_id": target["source_id"], "source_tuple": target["source_tuple"],
        "secret_id": target["secret_id"], "version_id": target["version_id"],
        "purpose": target["purpose"], "configuration_revision": target["configuration_revision"],
        "recovery_epoch_id": recovery_epoch_id, "attestation_sha256": attestation_digest,
        "rationale": request["rationale"], "evidence_ref": request["evidence_ref"],
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=15)).isoformat().replace("+00:00", "Z")}
    signature = Ed25519PrivateKey.from_private_bytes(operator_seed).sign(_canonical(approval))
    return {**approval, "signature": base64.b64encode(signature).decode("ascii")}


def _write_exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _private_file(path: Path) -> bytes:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.getuid()):
        raise ValueError("committed custody file is unsafe")
    return path.read_bytes()


def _safe_response(instance_id: str, journal_id: str, issuer_id: str,
                   operator_id: str, issuer_public: bytes, operator_public: bytes) -> dict:
    return {"schema_version": 1, "profile": PROFILE, "status": "prepared",
            "installation_id": instance_id, "journal_id": journal_id,
            "issuer_key_id": issuer_id, "operator_key_id": operator_id,
            "issuer_public_sha256": hashlib.sha256(issuer_public).hexdigest(),
            "operator_public_sha256": hashlib.sha256(operator_public).hexdigest(),
            "restore_generation": 0, "recovery_epoch_id": None}


def _validate_directory(path: Path, expected: set[str]) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.getuid() or {item.name for item in path.iterdir()} != expected
            or any(item.is_symlink() for item in path.iterdir())):
        raise ValueError("committed custody directory is unsafe")


def _resume(root: Path, request: dict) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    runtime, authority, fence = (root / PATH_POLICY[name] for name in
        ("runtime_directory", "authority_directory", "fence_directory"))
    _validate_directory(runtime, {"issuer.key", "issuer.pub", "operator.pub", "material.key"})
    _validate_directory(authority, {"operator.key", "operator.pub", "issuer.pub", "host.json"})
    _validate_directory(fence, {"fence.json"})
    issuer_seed = _private_file(runtime / "issuer.key")
    operator_seed = _private_file(authority / "operator.key")
    issuer_public, operator_public = (_private_file(runtime / "issuer.pub"),
                                      _private_file(runtime / "operator.pub"))
    material = _private_file(runtime / "material.key")
    local_auth_key = _private_file(root / "secrets/local-auth-key")
    if any(len(data) != 32 for data in (issuer_seed, operator_seed, issuer_public,
                                       operator_public, material, local_auth_key)):
        raise ValueError("committed key length is invalid")
    if len({issuer_seed, operator_seed, material, local_auth_key}) != 4:
        raise ValueError("committed private keys are not independent")
    pub = lambda seed: Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    if (pub(issuer_seed) != issuer_public or pub(operator_seed) != operator_public
            or issuer_public == operator_public):
        raise ValueError("committed key identities disagree")
    if (_private_file(authority / "issuer.pub") != issuer_public
            or _private_file(authority / "operator.pub") != operator_public):
        raise ValueError("host and runtime public keys disagree")
    api_config = json.loads(_private_file(root / PATH_POLICY["api_config"]),
        object_pairs_hook=_pairs, parse_float=_no_float, parse_constant=_no_float)
    host_config = json.loads(_private_file(authority / "host.json"),
        object_pairs_hook=_pairs, parse_float=_no_float, parse_constant=_no_float)
    fence_value = json.loads(_private_file(fence / "fence.json"),
        object_pairs_hook=_pairs, parse_float=_no_float, parse_constant=_no_float)
    metadata = json.loads(_private_file(root / "instance.json"), object_pairs_hook=_pairs)
    tuple_value = metadata.get("local_recovery_custody") if isinstance(metadata, dict) else None
    if (not isinstance(tuple_value, dict)
            or set(tuple_value) != {"schema_version", "profile", "installation_id", "journal_id",
                                    "restore_generation", "recovery_epoch_id"}
            or type(tuple_value.get("restore_generation")) is not int
            or tuple_value["restore_generation"] < 0
            or (tuple_value["restore_generation"] == 0 and tuple_value["recovery_epoch_id"] is not None)
            or (tuple_value["restore_generation"] > 0
                and (not isinstance(tuple_value["recovery_epoch_id"], str)
                     or str(uuid.UUID(tuple_value["recovery_epoch_id"])) != tuple_value["recovery_epoch_id"]))):
        raise ValueError("committed restore custody tuple is invalid")
    expected_tuple = {"schema_version": 1, "profile": PROFILE,
        "installation_id": request["installation_id"], "journal_id": request["journal_id"],
        "restore_generation": tuple_value["restore_generation"],
        "recovery_epoch_id": tuple_value["recovery_epoch_id"]}
    if (not isinstance(metadata, dict)
            or metadata.get("installation_id") != request["installation_id"]
            or metadata.get("local_recovery_journal_id") != request["journal_id"]
            or tuple_value != expected_tuple
            or fence_value != expected_tuple
            or api_config.get("installation_id") != request["installation_id"]
            or api_config.get("profile") != PROFILE
            or host_config.get("installation_id") != request["installation_id"]
            or host_config.get("profile") != PROFILE):
        raise ValueError("committed custody identity disagrees with request")
    issuer_id, operator_id = api_config.get("issuer_key_id"), api_config.get("operator_key_id")
    if (not isinstance(issuer_id, str) or str(uuid.UUID(issuer_id)) != issuer_id
            or not isinstance(operator_id, str) or str(uuid.UUID(operator_id)) != operator_id
            or host_config.get("issuer_key_id") != issuer_id
            or host_config.get("operator_key_id") != operator_id):
        raise ValueError("committed key identifiers disagree")
    expected_api = {"schema_version": 1, "profile": PROFILE,
        "installation_id": request["installation_id"], "issuer_key_id": issuer_id,
        "operator_key_id": operator_id,
        "operator_id": f"local-host:{request['installation_id']}",
        "issuer_public_key_file": "/run/uvm-local-recovery/issuer.pub",
        "issuer_private_key_file": "/run/uvm-local-recovery/issuer.key",
        "operator_public_key_file": "/run/uvm-local-recovery/operator.pub",
        "material_key_file": "/run/uvm-local-recovery/material.key",
        "restore_fence_file": "/run/volt-restore-fence/fence.json",
        "proof_store": {"kind": "postgresql", "schema_revision": "0067"}}
    expected_host = {"schema_version": 1, "profile": PROFILE,
        "installation_id": request["installation_id"],
        "operator_id": f"local-host:{request['installation_id']}",
        "operator_key_id": operator_id,
        "operator_private_key_file": "/authority/operator.key",
        "operator_public_key_file": "/authority/operator.pub",
        "issuer_key_id": issuer_id, "issuer_public_key_file": "/authority/issuer.pub",
        "restore_fence_file": "/authority/fence/fence.json",
        "journal_file": "/authority/instance.json"}
    if api_config != expected_api or host_config != expected_host:
        raise ValueError("committed closed configuration differs from admitted policy")
    return _safe_response(request["installation_id"], request["journal_id"],
                          issuer_id, operator_id, issuer_public, operator_public)


def prepare(args) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    request = _read_request(sys.stdin)
    root = Path(args.instance_root)
    root_info = root.lstat()
    if (root.is_symlink() or not stat.S_ISDIR(root_info.st_mode)
            or stat.S_IMODE(root_info.st_mode) != 0o700 or root_info.st_uid != os.getuid()):
        raise ValueError("instance root is unsafe")
    metadata_path = root / "instance.json"
    metadata = json.loads(_private_file(metadata_path), object_pairs_hook=_pairs,
                          parse_float=_no_float, parse_constant=_no_float)
    if (not isinstance(metadata, dict) or metadata.get("mode") != "local"
            or metadata.get("installation_id") != request["installation_id"]
            or metadata.get("local_recovery_journal_id") != request["journal_id"]
            or metadata.get("established") is not False):
        raise ValueError("instance identity does not match preparation request")
    tuple_value = {"schema_version": 1, "profile": PROFILE,
                   "installation_id": request["installation_id"],
                   "journal_id": request["journal_id"], "restore_generation": 0,
                   "recovery_epoch_id": None}

    runtime = root / PATH_POLICY["runtime_directory"]
    authority = root / PATH_POLICY["authority_directory"]
    fence = root / PATH_POLICY["fence_directory"]
    created = []
    try:
        present = [directory.exists() or directory.is_symlink()
                   for directory in (runtime, authority, fence)]
        if any(present):
            if not all(present):
                raise ValueError("partial custody preparation exists")
            response = _resume(root, request)
            sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
            return
        if "local_recovery_custody" in metadata:
            raise ValueError("custody journal exists but committed key directories are missing")
        for directory in (runtime, authority, fence):
            directory.mkdir(mode=0o700)
            created.append(directory)
        issuer_seed, operator_seed, material_key = (secrets.token_bytes(32) for _ in range(3))
        issuer_private = Ed25519PrivateKey.from_private_bytes(issuer_seed)
        operator_private = Ed25519PrivateKey.from_private_bytes(operator_seed)
        issuer_public = issuer_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        operator_public = operator_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        issuer_id, operator_id = str(uuid.uuid4()), str(uuid.uuid4())
        api_config = {"schema_version": 1, "profile": PROFILE,
            "installation_id": request["installation_id"], "issuer_key_id": issuer_id,
            "operator_key_id": operator_id,
            "operator_id": f"local-host:{request['installation_id']}",
            "issuer_public_key_file": "/run/uvm-local-recovery/issuer.pub",
            "issuer_private_key_file": "/run/uvm-local-recovery/issuer.key",
            "operator_public_key_file": "/run/uvm-local-recovery/operator.pub",
            "material_key_file": "/run/uvm-local-recovery/material.key",
            "restore_fence_file": "/run/volt-restore-fence/fence.json",
            "proof_store": {"kind": "postgresql", "schema_revision": "0067"}}
        host_config = {"schema_version": 1, "profile": PROFILE,
            "installation_id": request["installation_id"],
            "operator_id": f"local-host:{request['installation_id']}",
            "operator_key_id": operator_id,
            "operator_private_key_file": "/authority/operator.key",
            "operator_public_key_file": "/authority/operator.pub",
            "issuer_key_id": issuer_id, "issuer_public_key_file": "/authority/issuer.pub",
            "restore_fence_file": "/authority/fence/fence.json",
            "journal_file": "/authority/instance.json"}
        values = (
            (runtime / "issuer.key", issuer_seed),
            (runtime / "issuer.pub", issuer_public),
            (runtime / "operator.pub", operator_public),
            (runtime / "material.key", material_key),
            (authority / "operator.key", operator_seed),
            (authority / "operator.pub", operator_public),
            (authority / "issuer.pub", issuer_public),
            (authority / "host.json", _canonical(host_config) + b"\n"),
            (fence / "fence.json", _canonical(tuple_value) + b"\n"),
            (root / PATH_POLICY["api_config"], _canonical(api_config) + b"\n"),
        )
        for path, data in values:
            _write_exclusive(path, data)
        for directory in (runtime, authority, fence, root):
            directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        metadata["local_recovery_custody"] = tuple_value
        temp = root / f".instance.json.{secrets.token_hex(8)}"
        _write_exclusive(temp, json.dumps(metadata, sort_keys=True, indent=2).encode() + b"\n")
        os.replace(temp, metadata_path)
        os.chmod(metadata_path, 0o600)
        directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        # Partial preparation is deliberately not repaired or regenerated on
        # resume. The next invocation will fail closed on existing files.
        raise
    response = _safe_response(request["installation_id"], request["journal_id"],
                              issuer_id, operator_id, issuer_public, operator_public)
    sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")


def validate(args) -> None:
    request = _read_request(sys.stdin)
    root = Path(args.instance_root)
    expected = _request_for_instance(root)
    if request != expected:
        raise ValueError("validation request differs from the committed instance identity")
    response = _resume(root, request)
    sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")


def request(args) -> None:
    value = _request_for_instance(Path(args.instance_root))
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def approve(args) -> None:
    if args.authority_config != "/authority/host.json":
        raise ValueError("authority config path is not the fixed admitted mount")
    host_config = json.loads(_private_file(Path(args.authority_config)), object_pairs_hook=_pairs,
                             parse_float=_no_float, parse_constant=_no_float)
    request_document = _read_document(sys.stdin)
    fence = json.loads(_private_file(Path("/authority/fence/fence.json")), object_pairs_hook=_pairs,
                       parse_float=_no_float, parse_constant=_no_float)
    journal = json.loads(_private_file(Path("/authority/instance.json")), object_pairs_hook=_pairs,
                         parse_float=_no_float, parse_constant=_no_float)
    approval = approve_document(request_document, host_config,
        _private_file(Path("/authority/operator.key")),
        _private_file(Path("/authority/operator.pub")),
        _private_file(Path("/authority/issuer.pub")), fence, journal)
    sys.stdout.write(json.dumps(approval, sort_keys=True, separators=(",", ":")) + "\n")


def targets_request(args) -> None:
    root = Path(args.instance_root)
    request = _request_for_instance(root)
    response = {"schema_version": 1, "profile": PROFILE,
                "installation_id": request["installation_id"]}
    sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")


def select_target(args) -> None:
    targets_doc = _read_document(sys.stdin)
    if (set(targets_doc) != {"schema_version", "profile", "installation_id", "targets"}
            or type(targets_doc["schema_version"]) is not int or targets_doc["schema_version"] != 1
            or targets_doc["profile"] != PROFILE or not isinstance(targets_doc["targets"], list)):
        raise ValueError("scanner target response schema is invalid")
    installation_id = _uuid(targets_doc["installation_id"])
    if (not isinstance(args.source, str) or not args.source.strip() or len(args.source) > 256
            or any(ord(character) < 0x20 or ord(character) == 0x7f for character in args.source)):
        raise ValueError("source label is invalid")
    target_fields = {"connector_id", "source_id", "display_name", "account_label", "platform_id",
                     "state", "configuration_revision"}
    selected = []
    for target in targets_doc["targets"]:
        if (not isinstance(target, dict) or set(target) != target_fields
                or type(target["configuration_revision"]) is not int
                or target["configuration_revision"] < 1
                or any(not isinstance(target[key], str) or not target[key]
                       for key in ("display_name", "account_label", "platform_id", "state"))):
            raise ValueError("scanner target response contains an invalid entry")
        _uuid(target["connector_id"])
        _uuid(target["source_id"])
        if f"{target['display_name']} [{target['account_label']}]" == args.source:
            selected.append(target)
    if len(selected) != 1:
        raise ValueError("source label must identify exactly one scanner")
    if any(not isinstance(value, str) or not value.strip() or len(value) > 2048
           for value in (args.rationale, args.evidence_ref)):
        raise ValueError("recovery rationale or evidence reference is invalid")
    target = selected[0]
    request = {"schema_version": 1, "profile": PROFILE,
        "installation_id": installation_id, "connector_id": target["connector_id"],
        "source_id": target["source_id"], "configuration_revision": target["configuration_revision"],
        "rationale": args.rationale, "evidence_ref": args.evidence_ref}
    sys.stdout.write(json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n")


def summarize_import(args) -> None:
    receipt = _read_document(sys.stdin)
    expected = {"schema_version", "profile", "operation", "installation_id", "connector_id",
        "source_id", "approval_id", "approval_expires_at", "state", "audit_event_id", "command_id"}
    if (set(receipt) != expected or type(receipt["schema_version"]) is not int
            or receipt["schema_version"] != 1 or receipt["profile"] != PROFILE
            or receipt["operation"] != "scanner_recovery_import" or receipt["state"] != "imported"):
        raise ValueError("scanner recovery import receipt schema is invalid")
    _timestamp(receipt["approval_expires_at"])
    response = {"source": args.source, "state": receipt["state"],
                "approval_expires_at": receipt["approval_expires_at"]}
    sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--request-stdin", action="store_true", required=True)
    prepare_parser.add_argument("--instance-root", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--request-stdin", action="store_true", required=True)
    validate_parser.add_argument("--instance-root", required=True)
    request_parser = subparsers.add_parser("request")
    request_parser.add_argument("--instance-root", required=True)
    approve_parser = subparsers.add_parser("approve")
    approve_parser.add_argument("--request-stdin", action="store_true", required=True)
    approve_parser.add_argument("--authority-config", required=True)
    targets_parser = subparsers.add_parser("targets-request")
    targets_parser.add_argument("--instance-root", required=True)
    select_parser = subparsers.add_parser("select-target")
    select_parser.add_argument("--request-stdin", action="store_true", required=True)
    select_parser.add_argument("--source", required=True)
    select_parser.add_argument("--rationale", required=True)
    select_parser.add_argument("--evidence-ref", required=True)
    summary_parser = subparsers.add_parser("summarize-import")
    summary_parser.add_argument("--request-stdin", action="store_true", required=True)
    summary_parser.add_argument("--source", required=True)
    args = parser.parse_args()
    try:
        if args.operation == "prepare":
            prepare(args)
        elif args.operation == "validate":
            validate(args)
        elif args.operation == "approve":
            approve(args)
        elif args.operation == "targets-request":
            targets_request(args)
        elif args.operation == "select-target":
            select_target(args)
        elif args.operation == "summarize-import":
            summarize_import(args)
        else:
            request(args)
    except Exception:
        sys.stderr.write("local recovery custody preparation failed closed\n")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
