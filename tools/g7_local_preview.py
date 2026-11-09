#!/usr/bin/env python3
"""Manage a private, loopback-only VOLT G7 local preview container."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import ipaddress
import re
import secrets
import shutil
import subprocess
import uuid


def run(*args: str, capture: bool = False) -> str:
    result = subprocess.run(args, text=True, check=False,
                            stdout=subprocess.PIPE if capture else None)
    if result.returncode:
        raise SystemExit(result.returncode)
    return result.stdout.strip() if capture else ""


def state_dir(instance: str) -> Path:
    if not instance or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in instance):
        raise SystemExit("instance must contain only letters, digits, hyphen and underscore")
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
    return base / "volt/g7-preview" / instance


def secret(path: Path, size: int = 48) -> str:
    value = secrets.token_urlsafe(size)
    path.write_text(value + "\n", encoding="ascii")
    path.chmod(0o600)
    return value


def make_tls(directory: Path) -> None:
    """Create a private self-signed server cert and matching local client CA."""
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365",
        "-subj", "/CN=VOLT G7 local recovery CA", "-keyout", str(directory / "recovery-ca.key"),
        "-out", str(directory / "recovery-ca.crt"), capture=True)
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
        "-keyout", str(directory / "recovery-server.key"),
        "-out", str(directory / "recovery-server.csr"), capture=True)
    ext = directory / "recovery-server.ext"
    ext.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n", encoding="ascii")
    ext.chmod(0o600)
    run("openssl", "x509", "-req", "-in", str(directory / "recovery-server.csr"),
        "-CA", str(directory / "recovery-ca.crt"), "-CAkey", str(directory / "recovery-ca.key"),
        "-CAcreateserial", "-days", "365", "-sha256", "-extfile", str(ext),
        "-out", str(directory / "recovery-server.crt"), capture=True)
    (directory / "recovery-server.csr").unlink()
    ext.unlink()
    (directory / "recovery-ca.srl").unlink(missing_ok=True)
    (directory / "recovery-ca.key").unlink()
    (directory / "recovery-ca.crt").chmod(0o644)
    (directory / "recovery-server.crt").chmod(0o644)
    (directory / "recovery-server.key").chmod(0o600)


def oidc_configuration(api_origin: str, oidc_origin: str) -> dict:
    internal_origin = "http://127.0.0.1:9000"
    return {
        "schema_version": 1, "provider_id": "volt-local-preview",
        "issuer": oidc_origin, "discovery_url": internal_origin + "/.well-known/openid-configuration",
        "client_id": "volt-local-preview", "callback_url": api_origin + "/api/v1/auth/callback",
        "client_secret_file": "/run/uvm-g7-secrets/oidc_client_secret",
        "sync_secret_file": "/run/uvm-g7-secrets/oidc_sync_secret",
        "operator_secret_file": "/run/uvm-g7-secrets/oidc_operator_secret",
        "operator_actor_id": "volt-local-preview-operator", "allowed_algorithms": ["RS256"],
        "allowed_endpoint_origins": [api_origin, oidc_origin, internal_origin], "source_scope_ceilings": [],
        "group_mappings": {}, "mapping_revision": 1,
        "session_ttl_seconds": 3600, "heartbeat_max_age_seconds": 120,
    }


def preview_grantable_envelope() -> dict:
    return {
        "actions": ["access_group.read", "ownership.team.read", "ownership.team.manage"],
        "target_scope": {"group_ids": ["*"], "source_families": ["local"],
            "environments": ["*"], "service_ids": ["*"], "membership_mode": "all_current"},
        "source_scopes": [{"source_family": "local", "source_account_id": "volt-local-preview",
            "scope_key": "all"}],
        "limits": {"maximum_acceptance_days": None, "maximum_severity": None,
            "whole_group_confirmation": False, "allowed_environments": ["*"],
            "allowed_service_ids": ["*"], "allowed_sla_clock_bases": [],
            "allowed_sla_severities": [], "allowed_sla_start_sources": [],
            "maximum_sla_duration_seconds": None, "allow_sla_backfill": False,
            "maximum_deadline_extension_seconds": None, "allowed_identity_scalar_fields": {}},
        "separation_of_duties": {"approval_requires_distinct_actor": True,
            "prohibit_requester_approval": True, "required_approver_count": 1,
            "prohibited_action_pairs": []}}


def ingress_peer_cidrs(gateway: str) -> tuple[str, str]:
    address = ipaddress.ip_address(gateway)
    return ("127.0.0.1/32", f"{address}/{address.max_prefixlen}")


def ingress_hostnames() -> str:
    return "127.0.0.1,localhost"


def initialize(args) -> None:
    dirty = run("git", "status", "--porcelain", capture=True)
    if dirty:
        raise SystemExit("initialize from a committed, clean source revision so the image can be bound to an exact SHA")
    root = state_dir(args.instance)
    if root.exists():
        raise SystemExit(f"instance already initialized: {root}")
    root.mkdir(mode=0o700, parents=True)
    secrets_dir = root / "secrets"
    secrets_dir.mkdir(mode=0o700)
    for name, size in (("uvm_db_password", 32), ("ce_db_password", 32),
                       ("ce_admin_password", 32), ("ce_secret_key", 64),
                       ("ce_credential_key", 32), ("uvm_cursor_secret", 48),
                       ("oidc_client_secret", 48), ("oidc_sync_secret", 48),
                       ("oidc_operator_secret", 48)):
        secret(secrets_dir / name, size)
    make_tls(secrets_dir)
    api_port, oidc_port = args.api_port, args.oidc_port
    api_origin, oidc_origin = f"http://127.0.0.1:{api_port}", f"http://127.0.0.1:{oidc_port}"
    config = oidc_configuration(api_origin, oidc_origin)
    (root / "oidc.json").write_text(json.dumps(config, separators=(",", ":")) + "\n", encoding="utf-8")
    (root / "oidc.json").chmod(0o600)
    link = {"issuer": oidc_origin, "subject": "volt-local-preview-admin-subject",
        "principal_id": "volt-local-preview-admin", "display_label": "Synthetic Local Preview Administrator",
        "rationale": "Explicit local preview bootstrap", "evidence_ref": "local-preview-bootstrap"}
    (root / "operator-link.json").write_text(json.dumps(link, separators=(",", ":")) + "\n", encoding="utf-8")
    (root / "operator-link.json").chmod(0o600)
    owner_token = secrets.token_hex(32)
    suffix = owner_token[:16]
    helper_revision = run("git", "rev-parse", "HEAD", capture=True)
    metadata = {"instance": args.instance, "owner_token": owner_token,
        "container": f"volt-g7-preview-{args.instance}-{suffix}",
        "container_id": None, "container_resource_id": str(uuid.uuid4()),
        "network": f"volt-g7-preview-{args.instance}-{suffix}-net",
        "network_id": None, "network_resource_id": str(uuid.uuid4()),
        "volumes": {part: f"volt-g7-preview-{args.instance}-{suffix}-{part}" for part in ("postgres", "media", "state")},
        "volume_resource_ids": {part: str(uuid.uuid4()) for part in ("postgres", "media", "state")},
        "api_port": api_port, "oidc_port": oidc_port, "secrets_dir": str(secrets_dir),
        "lifecycle_state": "initializing",
        "source_revision": helper_revision, "helper_revision": helper_revision, "source_status": "clean"}
    (root / "instance.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    (root / "instance.json").chmod(0o600)
    print(f"initialized={root}")


def load(instance: str) -> tuple[Path, dict]:
    root = state_dir(instance)
    # Allow an intentionally symlinked XDG_STATE_HOME, but never let an
    # instance-name alias or metadata symlink redirect a lifecycle command.
    if root.is_symlink():
        raise SystemExit(f"refusing preview instance path: instance directory is a symlink: {instance}")
    try:
        admitted_root = root.resolve(strict=True)
        if not admitted_root.is_dir():
            raise SystemExit(f"refusing preview instance path: instance root is not a directory: {instance}")
        metadata_path = root / "instance.json"
        if metadata_path.is_symlink():
            raise SystemExit(f"refusing preview metadata: instance.json is a symlink: {instance}")
        metadata_real = metadata_path.resolve(strict=True)
        metadata_real.relative_to(admitted_root)
        info = json.loads(metadata_real.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"instance is not initialized: {instance}") from exc
    except ValueError as exc:
        raise SystemExit(f"refusing preview metadata outside instance root: {instance}") from exc
    if info.get("instance") != instance:
        raise SystemExit(f"refusing preview metadata: stored instance does not match requested instance {instance}")
    try:
        secrets_dir = Path(info["secrets_dir"]).resolve(strict=True)
        expected_secrets = (admitted_root / "secrets").resolve(strict=True)
        private_files = [(root / name).resolve(strict=True) for name in ("oidc.json", "operator-link.json")]
    except (KeyError, TypeError, OSError) as exc:
        raise SystemExit("refusing preview metadata: private files are missing or outside the instance root") from exc
    try:
        secrets_dir.relative_to(admitted_root)
        for private_file in private_files:
            private_file.relative_to(admitted_root)
    except ValueError as exc:
        raise SystemExit("refusing preview metadata: private files are outside the instance root") from exc
    if secrets_dir != expected_secrets:
        raise SystemExit("refusing preview metadata: secrets_dir does not reference this instance")
    return admitted_root, info


def save_instance(root: Path, info: dict) -> None:
    path = root / "instance.json"
    temporary = root / "instance.json.tmp"
    temporary.write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def exact_container(info: dict) -> bool:
    result = subprocess.run(("docker", "inspect", "--format",
        "{{.Id}}|{{index .Config.Labels \"volt.g7-preview.owner-token\"}}|{{index .Config.Labels \"volt.g7-preview.resource-id\"}}",
        info["container"]), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        if "no such object" in result.stderr.lower() or "not found" in result.stderr.lower():
            return False
        raise SystemExit(f"could not inspect preview container safely: {result.stderr.strip()}")
    fields = result.stdout.strip().split("|")
    if len(fields) != 3 or fields[0] != info.get("container_id") or fields[1] != info.get("owner_token") or fields[2] != info.get("container_resource_id"):
        raise SystemExit("refusing preview container: ownership token or exact created container ID does not match")
    return True


def exact_volume(info: dict, part: str) -> bool:
    name = info["volumes"][part]
    result = subprocess.run(("docker", "volume", "inspect", "--format",
        "{{index .Labels \"volt.g7-preview.owner-token\"}}|{{index .Labels \"volt.g7-preview.resource-id\"}}", name),
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        if "no such volume" in result.stderr.lower() or "not found" in result.stderr.lower():
            return False
        raise SystemExit(f"could not inspect preview volume safely: {result.stderr.strip()}")
    fields = result.stdout.strip().split("|")
    if len(fields) != 2 or fields[0] != info.get("owner_token") or fields[1] != info.get("volume_resource_ids", {}).get(part):
        raise SystemExit(f"refusing preview volume {name}: ownership token or created resource ID does not match")
    return True


def exact_network(info: dict) -> bool:
    result = subprocess.run(("docker", "network", "inspect", "--format",
        "{{.Id}}|{{index .Labels \"volt.g7-preview.owner-token\"}}|{{index .Labels \"volt.g7-preview.resource-id\"}}",
        info["network"]), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        if "no such network" in result.stderr.lower() or "not found" in result.stderr.lower():
            return False
        raise SystemExit(f"could not inspect preview network safely: {result.stderr.strip()}")
    fields = result.stdout.strip().split("|")
    if len(fields) != 3 or fields[0] != info.get("network_id") or fields[1] != info.get("owner_token") or fields[2] != info.get("network_resource_id"):
        raise SystemExit("refusing preview network: ownership token or exact created network ID does not match")
    return True


def preflight(info: dict, *, require_container: bool = False, require_complete: bool = False) -> dict:
    """Validate every existing resource before any Docker mutation."""
    container_exists = exact_container(info)
    network_exists = exact_network(info)
    volumes_exist = {part: exact_volume(info, part) for part in info["volumes"]}
    resources = {"container": container_exists, "network": network_exists, "volumes": volumes_exist}
    established = info.get("lifecycle_state") == "established" or info.get("container_id") is not None
    if require_complete and established:
        missing = [name for name, present in (("container", container_exists), ("network", network_exists),
            *((f"volume:{part}", present) for part, present in volumes_exist.items())) if not present]
        if missing:
            raise SystemExit("refusing established preview with missing owned resources: " + ", ".join(missing) +
                "; inspect retained evidence and use explicit destroy only for verified survivors")
    if require_container and not container_exists:
        raise SystemExit("refusing preview operation: the exact owned container is absent")
    return resources


SUPPORTED_PREVIEW_PLATFORM = "linux/amd64"
_IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SOURCE_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")


def start_mode(args) -> tuple[bool, dict | None]:
    no_build = bool(getattr(args, "no_build", False))
    image_id = getattr(args, "expected_image_id", None)
    source_revision = getattr(args, "expected_image_source_revision", None)
    version = getattr(args, "expected_image_version", None)
    platform = getattr(args, "expected_platform", None)
    supplied = any(value is not None for value in (image_id, source_revision, version, platform))
    if not no_build:
        if supplied:
            raise SystemExit("image admission metadata requires --no-build")
        return False, None
    if getattr(args, "image", None) is not None:
        raise SystemExit("--image cannot be combined with --no-build; provide an immutable image ID")
    if any(value is None for value in (image_id, source_revision, version, platform)):
        raise SystemExit("--no-build requires --expected-image-id, --expected-image-source-revision, --expected-image-version, and --expected-platform")
    if not _IMAGE_ID_RE.fullmatch(image_id):
        raise SystemExit("refusing no-build image: expected image ID must be a full sha256 ID")
    if not _SOURCE_REVISION_RE.fullmatch(source_revision):
        raise SystemExit("refusing no-build image: expected image source revision must be a full commit SHA")
    if not _IMAGE_VERSION_RE.fullmatch(version):
        raise SystemExit("refusing no-build image: expected image version metadata is invalid")
    if platform != SUPPORTED_PREVIEW_PLATFORM:
        raise SystemExit(f"refusing no-build image: supported platform must be {SUPPORTED_PREVIEW_PLATFORM}")
    return True, {"id": image_id, "revision": source_revision, "version": version, "platform": platform}


def admit_loaded_image(expected: dict) -> str:
    """Verify a loaded image's immutable identity and provenance without mutation."""
    result = subprocess.run(("docker", "image", "inspect", expected["id"]), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise SystemExit("refusing no-build image: expected immutable image ID is unavailable")
    try:
        values = json.loads(result.stdout)
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
            raise ValueError("inspect result shape")
        image = values[0]
        config = image.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        actual_id = image.get("Id")
        os_name = image.get("Os")
        architecture = image.get("Architecture")
        if not isinstance(labels, dict) or not isinstance(os_name, str) or not isinstance(architecture, str):
            raise ValueError("required metadata absent")
        actual_platform = f"{os_name}/{architecture}"
        revision = labels.get("org.opencontainers.image.revision")
        version = labels.get("org.opencontainers.image.version")
        if not isinstance(revision, str) or not isinstance(version, str):
            raise ValueError("required labels absent")
    except (json.JSONDecodeError, TypeError, ValueError):
        raise SystemExit("refusing no-build image: required image metadata is missing or malformed") from None
    if not isinstance(actual_id, str) or not _IMAGE_ID_RE.fullmatch(actual_id):
        raise SystemExit("refusing no-build image: required immutable image ID metadata is missing")
    if actual_id != expected["id"]:
        raise SystemExit("refusing no-build image: immutable image ID mismatch")
    if revision != expected["revision"]:
        raise SystemExit("refusing no-build image: source revision label mismatch")
    if version != expected["version"]:
        raise SystemExit("refusing no-build image: version label mismatch")
    if actual_platform != expected["platform"]:
        raise SystemExit("refusing no-build image: platform metadata mismatch")
    return actual_id


def admit_built_image(image: str, revision: str) -> dict:
    """Read back the just-built image's immutable identity and provenance."""
    result = subprocess.run(("docker", "image", "inspect", image), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise SystemExit("refusing preview image: built image is unavailable")
    try:
        values = json.loads(result.stdout)
        row = values[0]
        config = row["Config"]
        labels = config["Labels"]
        image_id = row["Id"]
        platform = f"{row['Os']}/{row['Architecture']}"
        version = labels["org.opencontainers.image.version"]
        source = labels["org.opencontainers.image.revision"]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError):
        raise SystemExit("refusing preview image: required image metadata is missing or malformed") from None
    if not isinstance(image_id, str) or not _IMAGE_ID_RE.fullmatch(image_id):
        raise SystemExit("refusing preview image: immutable image ID is missing")
    if source != revision or version != "local-preview" or platform != SUPPORTED_PREVIEW_PLATFORM:
        raise SystemExit("refusing preview image: built image provenance or platform mismatch")
    return {"id": image_id, "revision": source, "version": version, "platform": platform}


def bind_initial_image(root: Path, info: dict, expected: dict) -> None:
    """Persist image identity before creating any container, network, or volume."""
    binding = {key: expected[key] for key in ("id", "revision", "version", "platform")}
    existing = info.get("image_binding")
    if existing is not None and existing != binding:
        raise SystemExit("refusing partially initialized preview: image binding differs; destroy and initialize a fresh instance")
    if existing is None:
        # Old partial state has resources but no durable image identity. It is
        # unsafe to infer that those resources belong to this launch attempt.
        resources = preflight(info, require_complete=False)
        if resources["container"] or resources["network"] or any(resources["volumes"].values()):
            raise SystemExit("refusing partially initialized preview without an image binding; destroy and initialize a fresh instance")
        info["image_binding"] = binding
        save_instance(root, info)


def start(args) -> None:
    no_build, expected_image = start_mode(args)
    root, info = load(args.instance)
    resources = preflight(info, require_complete=True)
    if resources["container"]:
        raise SystemExit(f"owned container already exists; use restart or stop first: {info['container']}")
    current = run("git", "rev-parse", "HEAD", capture=True)
    helper_revision = info.get("helper_revision", info.get("source_revision"))
    if current != helper_revision or run("git", "status", "--porcelain", capture=True):
        raise SystemExit("source revision changed after init; destroy and reinitialize from a committed clean helper revision")

    if no_build:
        # The helper checkout revision is intentionally distinct from the loaded
        # image's source revision. Both identities are recorded and checked.
        image = admit_loaded_image(expected_image)
    elif info.get("image_binding") is not None:
        if getattr(args, "image", None) is not None:
            raise SystemExit("refusing partially initialized preview: use its immutable bound image without --image")
        expected_image = info["image_binding"]
        if not info.get("image_mode"):
            raise SystemExit("refusing partially initialized preview without image mode; continue with the explicit no-build image admission options")
        image = admit_loaded_image(expected_image)
    else:
        image = getattr(args, "image", None) or f"volt:preview-{helper_revision}"
        run("docker", "build", "--platform", SUPPORTED_PREVIEW_PLATFORM,
            "--label", f"org.opencontainers.image.revision={helper_revision}",
            "--label", "org.opencontainers.image.version=local-preview", "-f", "Dockerfile.g7", "-t", image, ".")
        expected_image = admit_built_image(image, helper_revision)
    bind_initial_image(root, info, expected_image)

    if not info.get("image_mode"):
        info["image_mode"] = "loaded-image" if no_build else "build-from-helper-source"
        save_instance(root, info)

    container = info["container"]
    if not exact_network(info):
        run("docker", "network", "create", "--driver", "bridge", "--label",
            f"volt.g7-preview.owner-token={info['owner_token']}", "--label",
            f"volt.g7-preview.resource-id={info['network_resource_id']}", info["network"])
        netid = run("docker", "network", "inspect", "--format", "{{.Id}}", info["network"], capture=True)
        info["network_id"] = netid
        save_instance(root, info)
        if not exact_network(info):
            raise SystemExit("created private preview network failed ownership verification")
    for part, name in info["volumes"].items():
        if not exact_volume(info, part):
            run("docker", "volume", "create", "--label", f"volt.g7-preview.instance={args.instance}",
                "--label", f"volt.g7-preview.owner-token={info['owner_token']}", "--label",
                f"volt.g7-preview.resource-id={info['volume_resource_ids'][part]}", name)
            if not exact_volume(info, part):
                raise SystemExit(f"created preview volume failed ownership verification: {name}")
    gateway = run("docker", "network", "inspect", "--format", "{{(index .IPAM.Config 0).Gateway}}",
        info["network"], capture=True)
    allowed_peers = ingress_peer_cidrs(gateway)
    secret_dir = info["secrets_dir"]
    env = {
        "DD_ADMIN_USER": "admin", "DD_ADMIN_MAIL": "admin@localhost.invalid",
        "DD_ADMIN_FIRST_NAME": "Synthetic", "DD_ADMIN_LAST_NAME": "Operator",
        "DD_ALLOWED_HOSTS": "localhost,127.0.0.1", "DD_INITIALIZE": "true",
        "UVM_AUTH_MODE": "oidc", "UVM_OIDC_CONFIG": (root / "oidc.json").read_text().strip(),
        "UVM_OIDC_FIXTURE_SUBJECT": "volt-local-preview-admin-subject",
        "UVM_OIDC_FIXTURE_IDENTITIES": '[{"subject":"volt-local-preview-admin-subject","groups":[]}]',
        "UVM_OIDC_PROVIDER_PORT": "9000", "UVM_OIDC_BROWSER_AUTHORIZATION_ORIGIN": f"http://127.0.0.1:{info['oidc_port']}",
        "UVM_OIDC_INTERNAL_ENDPOINT_ORIGIN": "http://127.0.0.1:9000",
        "UVM_G3_BOOTSTRAP_PRINCIPAL": "volt-local-preview-admin",
        "UVM_NATIVE_BOOTSTRAP_PRINCIPALS": "volt-local-preview-admin",
        "UVM_NATIVE_GRANTABLE_ENVELOPE": json.dumps(preview_grantable_envelope(), separators=(",", ":")),
        "UVM_G7_RECOVERY_TLS_CERT_FILE": "/run/uvm-g7-secrets/recovery-server.crt",
        "UVM_G7_RECOVERY_TLS_KEY_FILE": "/run/uvm-g7-secrets/recovery-server.key",
        "UVM_G7_RECOVERY_TLS_CA_FILE": "/run/uvm-g7-secrets/recovery-ca.crt",
        "UVM_API_HOST": "0.0.0.0", "UVM_API_PORT": "8000",
        "UVM_INGRESS_ALLOWED_PEER_CIDRS": ",".join(allowed_peers),
        "UVM_INGRESS_ALLOWED_HOSTS": ingress_hostnames(),
    }
    cmd = ["docker", "run", "-d", "--name", container,
        "--label", f"volt.g7-preview.instance={args.instance}",
        "--label", f"volt.g7-preview.owner-token={info['owner_token']}",
        "--label", f"volt.g7-preview.resource-id={info['container_resource_id']}",
        "--network", info["network"],
        "--publish", f"127.0.0.1:{info['api_port']}:8000",
        "--publish", f"127.0.0.1:{info['oidc_port']}:9000",
        "--mount", f"type=bind,src={secret_dir},dst=/run/secrets,readonly"]
    for part, volume in info["volumes"].items():
        target = {"postgres": "/var/lib/postgresql/data", "media": "/app/media", "state": "/opt/uvm/state"}[part]
        cmd += ["--mount", f"type=volume,src={volume},dst={target}"]
    for key, value in env.items():
        cmd += ["--env", f"{key}={value}"]
    # Reinspect after resource creation to close the check/use window, then
    # launch every path by content ID rather than a mutable repository tag.
    image = admit_loaded_image(expected_image)
    cmd.append(expected_image["id"])
    info["image"] = image
    info["image_binding"] = {key: expected_image[key] for key in ("id", "revision", "version", "platform")}
    info["image_mode"] = info.get("image_mode") or ("loaded-image" if no_build else "build-from-helper-source")
    info["helper_revision"] = helper_revision
    info["image_source_revision"] = expected_image["revision"]
    info["image_version"] = expected_image["version"]
    info["image_platform"] = expected_image["platform"]
    info["container_id"] = run(*cmd, capture=True)
    save_instance(root, info)
    if not exact_container(info):
        raise SystemExit("created preview container failed ownership verification")
    info["image_id"] = run("docker", "inspect", "--format", "{{.Image}}", container, capture=True)
    if info["image_id"] != expected_image["id"]:
        raise SystemExit("refusing preview container: launched image ID differs from admitted image")
    info["lifecycle_state"] = "established"
    save_instance(root, info)
    print(f"container={container}\nimage={image}\nimage_id={info['image_id']}\nurl=http://127.0.0.1:{info['api_port']}/")


def docker_for(args, action: str) -> None:
    _root, info = load(args.instance)
    container = info["container"]
    if action == "status":
        if not exact_container(info):
            print(f"container=absent name={container}")
            return
        run("docker", "ps", "-a", "--filter", f"name={container}", "--format", "{{.Names}} {{.Status}} {{.Image}}")
        return
    preflight(info, require_container=True, require_complete=True)
    run("docker", action, container)


def wait_healthy(args) -> None:
    _root, info = load(args.instance)
    preflight(info, require_container=True, require_complete=True)
    import time
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        status = run("docker", "inspect", "--format", "{{.State.Health.Status}}", info["container"], capture=True)
        if status == "healthy":
            print(f"health=healthy container={info['container']}")
            return
        if status in {"unhealthy", "none"}:
            raise SystemExit(f"container health did not become healthy (status={status})")
        time.sleep(5)
    raise SystemExit(f"container health wait timed out after {args.timeout} seconds")


def link_admin(args) -> None:
    root, info = load(args.instance)
    preflight(info, require_container=True, require_complete=True)
    link = (root / "operator-link.json").read_text(encoding="utf-8").strip()
    # The operator credential is read inside the container and is never included in argv/output.
    program = "import json,urllib.request; p='/run/uvm-g7-secrets/oidc_operator_secret'; token=open(p).read().strip(); body=" + repr(link) + "; r=urllib.request.Request('http://127.0.0.1:8000/api/v1/auth/operator/links',data=body.encode(),headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'}); print(urllib.request.urlopen(r,timeout=10).read().decode())"
    run("docker", "exec", "-i", info["container"], "/opt/uvm/venv/bin/python", "-c", program)


def verify_private_ingress(info: dict, evidence: Path) -> None:
    ip = run("docker", "inspect", "--format",
        f'{{{{(index .NetworkSettings.Networks "{info["network"]}").IPAddress}}}}',
        info["container"], capture=True)
    probe_name = f"{info['container']}-peer-probe"
    probe = subprocess.run(("docker", "inspect", probe_name),
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if probe.returncode == 0:
        raise SystemExit("refusing peer probe because its exact one-shot name already exists")
    script = ("import json,sys,urllib.error,urllib.request; url=sys.argv[1]\n"
        "try: urllib.request.urlopen(url,timeout=8)\n"
        "except urllib.error.HTTPError as e:\n"
        " body=json.loads(e.read()); code=body.get('error',{}).get('code'); "
        "print(f'status={e.code} code={code}'); sys.exit(0 if e.code==403 and code=='ingress_peer_forbidden' else 3)\n"
        "except Exception as e: print('unexpected_transport_error='+type(e).__name__); sys.exit(4)\n"
        "else: print('unexpected_peer_access=allowed'); sys.exit(5)")
    cidfile = evidence / f"ingress-peer-probe-{uuid.uuid4()}.cid"
    result = subprocess.run(("docker", "run", "--rm", "--cidfile", str(cidfile), "--name", probe_name,
        "--label", f"volt.g7-preview.owner-token={info['owner_token']}",
        "--label", f"volt.g7-preview.resource-id={uuid.uuid4()}", "--network", info["network"],
        "--entrypoint", "/opt/uvm/venv/bin/python", info["image"], "-c", script,
        f"http://{ip}:8000/healthz"), text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False)
    peer_id = cidfile.read_text(encoding="ascii").strip() if cidfile.exists() else "missing"
    cleanup = subprocess.run(("docker", "inspect", peer_id), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False) if peer_id != "missing" else None
    cleanup_exit = cleanup.returncode if cleanup else "unavailable"
    text = (f"command=docker run --rm --cidfile {cidfile} --name {probe_name} --network {info['network']} "
        f"--entrypoint /opt/uvm/venv/bin/python {info['image']} -c <peer-check> http://{ip}:8000/healthz\n"
        f"container_id={peer_id}\nexit={result.returncode}\n{result.stdout}"
        f"post_cleanup_docker_inspect_exit={cleanup_exit}\n")
    (evidence / "ingress-peer-denial.txt").write_text(text, encoding="utf-8")
    if result.returncode:
        raise SystemExit(f"unauthorized peer ingress did not return the expected 403 (exit={result.returncode})")


def destroy(args) -> None:
    root, info = load(args.instance)
    container = info["container"]
    resources = preflight(info)
    if resources["container"]:
        run("docker", "rm", "-f", container)
    for part, volume in info["volumes"].items():
        if resources["volumes"][part]:
            run("docker", "volume", "rm", volume)
    if resources["network"]:
        run("docker", "network", "rm", info["network"])
    shutil.rmtree(root)
    print(f"destroyed_owned_instance={args.instance}")


def smoke(args) -> None:
    _root, info = load(args.instance)
    preflight(info, require_container=True, require_complete=True)
    evidence = Path(args.evidence)
    evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    verify_private_ingress(info, evidence)
    command = ["node", "tools/g7_local_preview_smoke.mjs", "--origin",
        f"http://127.0.0.1:{info['api_port']}", "--issuer",
        f"http://127.0.0.1:{info['oidc_port']}", "--subject",
        "volt-local-preview-admin-subject", "--principal", "volt-local-preview-admin",
        "--evidence", str(evidence)]
    if args.readback:
        command.append("--readback")
    else:
        command.append("--initialize-development")
    subprocess.run(command, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init"); p.add_argument("instance"); p.add_argument("--api-port", type=int, default=8180); p.add_argument("--oidc-port", type=int, default=8190); p.set_defaults(fn=initialize)
    p = sub.add_parser("start"); p.add_argument("instance"); p.add_argument("--image", help="build output tag (default: revision-qualified preview tag)"); p.add_argument("--no-build", action="store_true", help="start an already-loaded, exactly admitted image without building"); p.add_argument("--expected-image-id"); p.add_argument("--expected-image-source-revision"); p.add_argument("--expected-image-version"); p.add_argument("--expected-platform"); p.set_defaults(fn=start)
    p = sub.add_parser("status"); p.add_argument("instance"); p.set_defaults(fn=lambda a: docker_for(a, "status"))
    p = sub.add_parser("wait"); p.add_argument("instance"); p.add_argument("--timeout", type=int, default=900); p.set_defaults(fn=wait_healthy)
    for cmd in ("stop", "restart"):
        p = sub.add_parser(cmd); p.add_argument("instance"); p.set_defaults(fn=lambda a, c=cmd: docker_for(a, c))
    p = sub.add_parser("link-admin"); p.add_argument("instance"); p.set_defaults(fn=link_admin)
    p = sub.add_parser("smoke"); p.add_argument("instance"); p.add_argument("--evidence", default="evidence/g7-local-preview"); p.add_argument("--readback", action="store_true"); p.set_defaults(fn=smoke)
    p = sub.add_parser("destroy"); p.add_argument("instance"); p.set_defaults(fn=destroy)
    args = parser.parse_args(); args.fn(args)


if __name__ == "__main__":
    main()
