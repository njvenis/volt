#!/usr/bin/env python3
"""Initialize and safely operate a source-free VOLT Compose instance."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import shutil
import subprocess
import sys
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (HTTPCookieProcessor, HTTPRedirectHandler, Request,
                            build_opener)

HISTORICAL_RC1_IMAGE = "ghcr.io/njvenis/volt@sha256:c0c49bc9c38a0ea946d1868748fcaadbf9e7e79dfd50b24d2b276c83c4d18497"
SECRET_SIZES = {"uvm_db_password": 32, "ce_db_password": 32, "ce_admin_password": 32,
                "ce_secret_key": 64, "ce_credential_key": 32, "uvm_cursor_secret": 48,
                "oidc_client_secret": 48, "oidc_sync_secret": 48, "oidc_operator_secret": 48}


def command(*args: str, capture: bool = False, env: dict | None = None,
            input_data: str | None = None, merge_stderr: bool = False) -> str:
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE if capture else None, check=False, env=env,
                            input=input_data)
    if result.returncode:
        detail = (result.stderr or result.stdout or "").strip() if capture else ""
        raise SystemExit(f"command failed ({result.returncode}): {' '.join(args)} {detail}")
    return result.stdout.strip() if capture else ""


def private_write(path: Path, value: str | bytes) -> None:
    path.write_bytes(value.encode() if isinstance(value, str) else value)
    path.chmod(0o600)


def private_secret(path: Path) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            raise OSError
        value = path.read_bytes()
    except OSError:
        raise SystemExit("OIDC client secret must be a readable, regular file") from None
    if not value.strip():
        raise SystemExit("OIDC client secret must be non-empty")
    return value


def allowed_host_names(raw: str) -> str:
    supplied = [item.strip().lower().rstrip(".") for item in raw.split(",") if item.strip()]
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", item)
           or ".." in item for item in supplied):
        raise SystemExit("allowed hosts must be exact DNS names or IPv4 addresses without ports or wildcards")
    # The supervised container's own readiness probes use loopback Host values.
    # Keep these exact names available without trusting any forwarded headers.
    return ",".join(dict.fromkeys(("localhost", "127.0.0.1", *supplied)))


def make_tls(directory: Path) -> None:
    command("openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "365",
            "-subj", "/CN=VOLT recovery CA", "-keyout", str(directory / "recovery-ca.key"),
            "-out", str(directory / "recovery-ca.crt"))
    command("openssl", "req", "-newkey", "rsa:3072", "-nodes", "-subj", "/CN=localhost",
            "-keyout", str(directory / "recovery-server.key"), "-out", str(directory / "server.csr"))
    ext = directory / "server.ext"
    private_write(ext, "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
    command("openssl", "x509", "-req", "-in", str(directory / "server.csr"), "-CA",
            str(directory / "recovery-ca.crt"), "-CAkey", str(directory / "recovery-ca.key"),
            "-CAcreateserial", "-days", "365", "-sha256", "-extfile", str(ext),
            "-out", str(directory / "recovery-server.crt"))
    command("openssl", "req", "-newkey", "rsa:3072", "-nodes", "-subj", "/CN=VOLT recovery client",
            "-keyout", str(directory / "recovery-client.key"), "-out", str(directory / "client.csr"))
    client_ext = directory / "client.ext"
    private_write(client_ext, "extendedKeyUsage=clientAuth\n")
    command("openssl", "x509", "-req", "-in", str(directory / "client.csr"), "-CA",
            str(directory / "recovery-ca.crt"), "-CAkey", str(directory / "recovery-ca.key"),
            "-CAcreateserial", "-days", "365", "-sha256", "-extfile", str(client_ext),
            "-out", str(directory / "recovery-client.crt"))
    for name in ("server.csr", "server.ext", "client.csr", "client.ext", "recovery-ca.key", "recovery-ca.srl"):
        (directory / name).unlink(missing_ok=True)
    (directory / "recovery-server.crt").chmod(0o644)
    (directory / "recovery-ca.crt").chmod(0o644)
    (directory / "recovery-server.key").chmod(0o600)
    (directory / "recovery-client.crt").chmod(0o644)
    (directory / "recovery-client.key").chmod(0o600)


def inspect_image(image: str, mode: str) -> dict:
    if not ("@sha256:" in image or re.fullmatch(r"sha256:[0-9a-f]{64}", image)):
        raise SystemExit("image must be an immutable registry digest or local sha256 image ID")
    try:
        item = json.loads(command("docker", "image", "inspect", image, capture=True))[0]
    except (json.JSONDecodeError, IndexError) as exc:
        raise SystemExit("could not inspect the selected image") from exc
    config = item.get("Config") or {}
    labels = config.get("Labels") or {}
    os_name, arch = item.get("Os"), item.get("Architecture")
    if (os_name, arch) != ("linux", "amd64"):
        raise SystemExit("selected image must be linux/amd64")
    if labels.get("org.volt.oidc-deployment-modes") != "demo,external":
        raise SystemExit("this image is not Compose-install compatible; RC1 does not support the OIDC config-file contract; pass an explicitly built candidate image with both deployment modes")
    source_snapshot = labels.get("org.volt.compose.source-snapshot", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", source_snapshot):
        raise SystemExit("Compose installs require a candidate image bound to an exact source snapshot archive")
    if labels.get("org.volt.compose-install.contract") != "1":
        raise SystemExit("candidate image lacks the Compose installation compatibility contract; rebuild from the reviewed source snapshot")
    revision = labels.get("org.opencontainers.image.revision", "")
    version = labels.get("org.opencontainers.image.version", "")
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or not version:
        raise SystemExit("image must declare source revision and version labels")
    return {"id": item["Id"], "source_revision": revision, "version": version,
            "source_snapshot": source_snapshot, "platform": f"{os_name}/{arch}",
            "registry_digests": item.get("RepoDigests", [])}


def validate_external(path: Path) -> dict:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit("external OIDC configuration must be readable JSON") from exc
    required = {"schema_version", "provider_id", "issuer", "discovery_url", "client_id", "callback_url",
        "client_secret_file", "sync_secret_file", "operator_secret_file", "operator_actor_id",
        "allowed_algorithms", "allowed_endpoint_origins", "source_scope_ceilings", "group_mappings",
        "mapping_revision", "session_ttl_seconds", "heartbeat_max_age_seconds"}
    if not isinstance(config, dict) or set(config) != required or config["schema_version"] != 1:
        raise SystemExit("external OIDC config must match the exact version 1 schema")
    for key in ("issuer", "discovery_url", "callback_url"):
        if not isinstance(config[key], str) or not config[key].startswith("https://"):
            raise SystemExit(f"external OIDC {key} must use HTTPS")
    callback = urlsplit(config["callback_url"])
    if callback.path != "/api/v1/auth/callback" or callback.query or callback.fragment or not callback.hostname:
        raise SystemExit("external OIDC callback must use the exact /api/v1/auth/callback path")
    origins = config["allowed_endpoint_origins"]
    if not isinstance(origins, list) or not origins or any(not isinstance(v, str) or not v.startswith("https://") for v in origins):
        raise SystemExit("external OIDC trusted endpoint origins must use HTTPS")
    if any(".invalid" in v or "localhost" in v or "127.0.0.1" in v for v in [*origins, config["issuer"], config["discovery_url"]]):
        raise SystemExit("external OIDC cannot reference demo or loopback endpoints")
    secret_paths = {"client_secret_file": "/run/uvm-g7-secrets/oidc_client_secret",
                    "sync_secret_file": "/run/uvm-g7-secrets/oidc_sync_secret",
                    "operator_secret_file": "/run/uvm-g7-secrets/oidc_operator_secret"}
    if any(config.get(key) != value for key, value in secret_paths.items()):
        raise SystemExit("OIDC config must use the installation's three mounted secret paths")
    return config


def choose_network() -> tuple[str, str]:
    used = []
    try:
        for identifier in command("docker", "network", "ls", "-q", capture=True).splitlines():
            item = json.loads(command("docker", "network", "inspect", identifier, capture=True))[0]
            used += [ipaddress.ip_network(c["Subnet"], strict=False)
                     for c in ((item.get("IPAM") or {}).get("Config") or []) if c.get("Subnet")]
    except (json.JSONDecodeError, IndexError, SystemExit):
        raise SystemExit("could not establish Docker network ownership safely")
    try:
        routes = json.loads(command("ip", "-j", "route", capture=True))
        used += [ipaddress.ip_network(r["dst"], strict=False)
                 for r in routes if r.get("dst") not in (None, "default")]
    except (OSError, SystemExit, json.JSONDecodeError, KeyError, ValueError):
        pass
    for second in range(240, 255):
        for third in range(256):
            network = ipaddress.ip_network(f"10.{second}.{third}.0/28")
            if all(not network.overlaps(existing) for existing in used):
                return str(network), str(network.network_address + 1)
    raise SystemExit("no unused private Docker subnet found; choose one after reviewing host and Docker routes")


def init(args) -> None:
    root = Path(args.directory).expanduser().absolute()
    if root.exists():
        raise SystemExit(f"refusing to initialize existing instance path: {root}")
    check_ports_available((args.http_port, args.recovery_port, args.oidc_port))
    image = args.image
    if not image:
        raise SystemExit(f"Compose installation requires --image with an explicitly built compatible candidate; historical RC1 {HISTORICAL_RC1_IMAGE} is retained for launcher users and lacks the Compose contract")
    admitted = inspect_image(image, args.mode)
    if args.mode == "external":
        oidc = validate_external(Path(args.external_config).expanduser())
        if not args.client_secret_file:
            raise SystemExit("external mode requires --client-secret-file for the configured OIDC client")
        external_client_secret = private_secret(Path(args.client_secret_file).expanduser())
        callback_host = urlsplit(oidc["callback_url"]).hostname.lower().rstrip(".")
        if callback_host not in {v.lower().rstrip(".") for v in args.allowed_hosts.split(",")}:
            raise SystemExit("external OIDC callback hostname must appear exactly in --allowed-hosts")
    else:
        external_client_secret = None
        args.bootstrap_principal = "volt-compose-demo-admin"
        if args.external_config:
            raise SystemExit("demo mode does not accept an external OIDC config")
        api_origin = f"http://127.0.0.1:{args.http_port}"
        oidc_origin = f"http://127.0.0.1:{args.oidc_port}"
        oidc = {"schema_version": 1, "provider_id": "volt-compose-demo", "issuer": oidc_origin,
            "discovery_url": "http://127.0.0.1:9000/.well-known/openid-configuration", "client_id": "volt-compose-demo",
            "callback_url": api_origin + "/api/v1/auth/callback",
            "client_secret_file": "/run/uvm-g7-secrets/oidc_client_secret",
            "sync_secret_file": "/run/uvm-g7-secrets/oidc_sync_secret",
            "operator_secret_file": "/run/uvm-g7-secrets/oidc_operator_secret",
            "operator_actor_id": "volt-compose-demo-operator", "allowed_algorithms": ["RS256"],
            "allowed_endpoint_origins": [api_origin, oidc_origin, "http://127.0.0.1:9000"],
            "source_scope_ceilings": [], "group_mappings": {}, "mapping_revision": 1,
            "session_ttl_seconds": 3600, "heartbeat_max_age_seconds": 120}
    if args.mode == "external":
        if not args.bootstrap_principal or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", args.bootstrap_principal):
            raise SystemExit("external mode requires --bootstrap-principal with a stable principal ID")
    project = re.sub(r"[^a-z0-9_-]", "", args.project.lower())
    if not project or not project[0].isalpha():
        raise SystemExit("project must start with a letter and contain only letters, numbers, '-' or '_'")
    hosts = allowed_host_names(args.allowed_hosts)
    for kind, name in [("volume", f"{project}_{part}") for part in ("postgres", "media", "state")]+[("network", f"{project}_network")]:
        if subprocess.run(("docker", kind, "inspect", name), stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, check=False).returncode == 0:
            raise SystemExit(f"refusing to adopt existing Docker resource {name}; choose a new project name")
    subnet, gateway = choose_network()
    root.mkdir(mode=0o700, parents=True)
    secrets_dir = root / "secrets"
    secrets_dir.mkdir(mode=0o700)
    for name, size in SECRET_SIZES.items():
        private_write(secrets_dir / name, secrets.token_urlsafe(size) + "\n")
    if args.mode == "external":
        private_write(secrets_dir / "oidc_client_secret", external_client_secret)
    make_tls(secrets_dir)
    private_write(root / "oidc.json", json.dumps(oidc, separators=(",", ":")) + "\n")
    compose_root = Path(__file__).resolve().parent
    owner_token = secrets.token_hex(32)
    scopes = oidc.get("source_scope_ceilings", [])
    envelope = {"actions": ["access_group.read", "ownership.team.read", "ownership.team.manage"],
        "target_scope": {"group_ids": ["*"], "source_families": ["*"], "environments": ["*"],
                         "service_ids": ["*"], "membership_mode": "all_current"},
        "source_scopes": scopes,
        "limits": {"maximum_acceptance_days": None, "maximum_severity": None,
            "whole_group_confirmation": False, "allowed_environments": ["*"], "allowed_service_ids": ["*"],
            "allowed_sla_clock_bases": [], "allowed_sla_severities": [], "allowed_sla_start_sources": [],
            "maximum_sla_duration_seconds": None, "allow_sla_backfill": False,
            "maximum_deadline_extension_seconds": None, "allowed_identity_scalar_fields": {}},
        "separation_of_duties": {"approval_requires_distinct_actor": True,
            "prohibit_requester_approval": True, "required_approver_count": 1,
            "prohibited_action_pairs": []}}
    env = "\n".join((f"VOLT_PROJECT={project}", f"VOLT_INSTANCE_DIR={root}", f"VOLT_IMAGE={image}",
                      f"VOLT_IMAGE_ID={admitted['id']}",
                      f"VOLT_BOOTSTRAP_PRINCIPAL={args.bootstrap_principal}",
                      "VOLT_NATIVE_GRANTABLE_ENVELOPE=" + json.dumps(envelope, separators=(",", ":")),
                      f"VOLT_OWNER_TOKEN={owner_token}", f"VOLT_SUBNET={subnet}", f"VOLT_GATEWAY={gateway}",
                      f"VOLT_HTTP_PORT={args.http_port}", f"VOLT_RECOVERY_PORT={args.recovery_port}",
                      f"VOLT_OIDC_PORT={args.oidc_port}", f"VOLT_ALLOWED_HOSTS={hosts}", ""))
    private_write(root / ".env", env)
    metadata = {"format_version": 1, "project": project, "mode": args.mode, "image": image,
                "image_admission": admitted, "oidc_config_sha256": hashlib.sha256((root / "oidc.json").read_bytes()).hexdigest(),
                "compose_directory": str(compose_root), "owner_token": owner_token,
                "bootstrap_principal": args.bootstrap_principal,
                "ports": [args.http_port, args.recovery_port, args.oidc_port],
                "subnet": subnet, "gateway": gateway, "established": False, "initialized": True}
    metadata["env_sha256"] = hashlib.sha256((root / ".env").read_bytes()).hexdigest()
    private_write(root / "instance.json", json.dumps(metadata, indent=2) + "\n")
    print(f"instance={root}\nmode={args.mode}\nimage_id={admitted['id']}\nsource_revision={admitted['source_revision']}\nversion={admitted['version']}")


def load_instance(path: str) -> tuple[Path, dict]:
    root = Path(path).expanduser().absolute()
    if root.is_symlink() or (root / "instance.json").is_symlink() or (root / ".env").is_symlink():
        raise SystemExit("refusing symlinked instance metadata")
    try:
        metadata = json.loads((root / "instance.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit("instance is not initialized") from exc
    if metadata.get("format_version") != 1 or metadata.get("initialized") is not True:
        raise SystemExit("instance metadata is not recognized")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", metadata.get("bootstrap_principal", "")):
        raise SystemExit("instance bootstrap principal metadata is invalid")
    for name in (*SECRET_SIZES, "recovery-server.crt", "recovery-server.key", "recovery-client.crt",
                 "recovery-client.key", "recovery-ca.crt"):
        secret = root / "secrets" / name
        if secret.is_symlink() or not secret.is_file() or not secret.read_bytes().strip():
            raise SystemExit("instance secret or recovery identity file is missing, empty or not regular")
    actual = hashlib.sha256((root / "oidc.json").read_bytes()).hexdigest()
    if actual != metadata.get("oidc_config_sha256"):
        raise SystemExit("OIDC config changed after initialization; use explicit reconfigure after review")
    return root, metadata


def compose_environment() -> dict[str, str]:
    """Keep Compose interpolation owned by the admitted instance .env only."""
    return {k: v for k, v in os.environ.items()
            if not k.startswith(("VOLT_", "COMPOSE_")) and k != "ENV"}


def resolved_compose(root: Path, info: dict):
    files = ["-f", str(Path(info["compose_directory"]) / "compose.yaml")]
    if info["mode"] == "demo":
        files += ["-f", str(Path(info["compose_directory"]) / "demo.yaml")]
    envfile = root / ".env"
    if hashlib.sha256(envfile.read_bytes()).hexdigest() != info.get("env_sha256"):
        raise SystemExit("instance environment file changed after admission; refusing Compose operation")
    clean_env = compose_environment()
    resolved = json.loads(command("docker", "compose", *files, "--env-file", str(envfile),
        "-p", info["project"], "config", "--format", "json", capture=True, env=clean_env))
    service = resolved.get("services", {}).get("volt", {})
    expected_mounts = {
        "/var/lib/postgresql/data": f"{info['project']}_postgres",
        "/app/media": f"{info['project']}_media",
        "/opt/uvm/state": f"{info['project']}_state",
        "/etc/volt/oidc.json": str(root / "oidc.json"),
    }
    volume_names = resolved.get("volumes", {})
    actual_mounts = {item.get("target"): (volume_names.get(item.get("source"), {}).get("name", item.get("source"))
                                           if item.get("type") == "volume" else item.get("source"))
                     for item in service.get("volumes", [])}
    labels = service.get("labels", {})
    if (service.get("image") != info["image"] or actual_mounts != expected_mounts or
            resolved.get("networks", {}).get("application", {}).get("name") != f"{info['project']}_network" or
            labels.get("volt.compose.owner-token") != info["owner_token"] or
            resolved.get("volumes", {}).get("postgres", {}).get("name") != f"{info['project']}_postgres" or
            resolved.get("volumes", {}).get("media", {}).get("name") != f"{info['project']}_media" or
            resolved.get("volumes", {}).get("state", {}).get("name") != f"{info['project']}_state"):
        raise SystemExit("resolved Compose image, mounts, network, volumes or ownership differ from admitted instance metadata")
    return files, envfile, clean_env


def compose(args, action: str) -> None:
    root, info = load_instance(args.directory)
    if action == "up" and info.get("restore_pending") and not info.get("restore_imported"):
        raise SystemExit("offline restore volumes must be imported and admitted with restore-admit before any runtime starts")
    files, envfile, clean_env = resolved_compose(root, info)
    if action == "up":
        admitted = inspect_image(info["image"], info["mode"])
        if admitted["id"] != info["image_admission"]["id"]:
            raise SystemExit("selected image identity changed since initialization")
        check_owned_resources(info, allow_missing=not info.get("established"))
        current = subprocess.run(("docker", "container", "inspect", f"{info['project']}-volt-1",
                                  "--format", "{{.State.Running}}"), capture_output=True, text=True)
        if current.returncode != 0 or current.stdout.strip().lower() != "true":
            check_ports_available(info.get("ports", ()))
    else:
        check_owned_resources(info, allow_missing=True)
    if action == "up":
        info.pop("backup_inventory", None)
        private_write(root / "instance.json", json.dumps(info, indent=2) + "\n")
    command("docker", "compose", *files, "--env-file", str(envfile), "-p", info["project"], action,
            *( ["-d"] if action == "up" else ["--timeout", "600"] if action == "stop" else []),
            env=clean_env)
    if action == "up":
        check_owned_resources(info, allow_missing=False)
        info["established"] = True
        private_write(root / "instance.json", json.dumps(info, indent=2) + "\n")
    elif action == "stop":
        verify_cold_stop(info)
        print("controlled shutdown verified; cold backup inventory may now be captured")


def verify_cold_stop(info: dict) -> None:
    name = f"{info['project']}-volt-1"
    item = json.loads(command("docker", "container", "inspect", name, capture=True))[0]
    state = item["State"]
    if (state.get("Running") or state.get("Paused") or state.get("Restarting") or
            state.get("OOMKilled") or state.get("ExitCode") != 0 or state.get("Error") or
            not state.get("StartedAt") or state["StartedAt"].startswith("0001-")):
        raise SystemExit("container lacks successful clean exit; do not capture a cold backup")
    # Restrict evidence to this start, so an earlier successful stop cannot mask a failure.
    logs = command("docker", "logs", "--since", state["StartedAt"], name, capture=True, merge_stderr=True)
    required = ("G7_STOP_PHASE=writers status=0", "G7_STOP_PHASE=workers status=0",
                "G7_STOP_DATABASE_STOPPED service=postgresql", "G7_STOP_PHASE=databases status=0",
                "G7_SHUTDOWN=controlled service_cleanup_status=0")
    if any(marker not in logs for marker in required) or "G7_STOP_ERROR" in logs:
        raise SystemExit("controlled supervisor cleanup evidence is missing or failed; do not capture a cold backup")


# Read-only, network-free helper: include names, types, ownership, permissions and
# file contents. Deliberately exclude access/modification times changed by reads.
INVENTORY_SCRIPT = r'''import hashlib,json,os,stat
from pathlib import Path
root=Path('/restore'); digest=hashlib.sha256(); count=0
for path in [root, *sorted(root.rglob('*'))]:
    st=path.lstat(); kind=stat.S_IFMT(st.st_mode); content=None
    if stat.S_ISREG(st.st_mode):
        h=hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024*1024), b''): h.update(block)
        content=h.hexdigest()
    elif stat.S_ISLNK(st.st_mode): content=os.readlink(path)
    elif not stat.S_ISDIR(st.st_mode): raise SystemExit('unsupported special file in offline store')
    record=[str(path.relative_to(root)),kind,stat.S_IMODE(st.st_mode),st.st_uid,st.st_gid,content]
    digest.update(json.dumps(record,separators=(',',':')).encode()+b'\n')
    if path!=root: count+=1
print(json.dumps({'sha256':digest.hexdigest(),'entries':count,'postgres_version':(root/'PG_VERSION').read_text().strip() if (root/'PG_VERSION').is_file() else None}))
'''


def volume_inventory(info: dict, store: str) -> dict:
    name = f"{info['project']}_{store}"
    # --mount fails if a volume is missing only after Docker may create it; check
    # explicitly before invoking any helper and verify exact ownership first.
    command("docker", "volume", "inspect", name, capture=True)
    return json.loads(command("docker", "run", "--rm", "--network", "none", "--read-only",
        "--user", "0:0", "--mount", f"type=volume,src={name},dst=/restore,readonly",
        "--entrypoint", "/opt/uvm/venv/bin/python", info["image_admission"]["id"],
        "-c", INVENTORY_SCRIPT, capture=True))


def record_backup(args) -> None:
    root, info = load_instance(args.directory)
    check_owned_resources(info, allow_missing=False)
    verify_cold_stop(info)
    info["backup_inventory"] = {store: volume_inventory(info, store)
                                for store in ("postgres", "media", "state")}
    if not info["backup_inventory"]["postgres"]["postgres_version"]:
        raise SystemExit("PostgreSQL inventory lacks PG_VERSION")
    private_write(root / "instance.json", json.dumps(info, indent=2) + "\n")
    print("all three cold store inventories recorded; copy instance metadata with the archives")


def check_owned_resources(info: dict, *, allow_missing: bool) -> None:
    owner = info["owner_token"]
    project = info["project"]
    specs = [("volume", f"{project}_{part}") for part in ("postgres", "media", "state")]
    specs += [("network", f"{project}_network"), ("container", f"{project}-volt-1")]
    for kind, name in specs:
        exists = subprocess.run(("docker", kind, "inspect", name), stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, check=False).returncode == 0
        if not exists:
            if allow_missing:
                continue
            raise SystemExit(f"refusing established instance with missing owned resource: {name}")
        field = ".Config.Labels" if kind == "container" else ".Labels"
        actual = command("docker", kind, "inspect", name, "--format",
                         f'{{{{index {field} "volt.compose.owner-token"}}}}', capture=True)
        if actual != owner:
            raise SystemExit(f"refusing resource without exact instance owner token: {name}")


def check_ports_available(ports) -> None:
    if len(ports) != 3 or any(type(port) is not int or not 1 <= port <= 65535 for port in ports) or len(set(ports)) != 3:
        raise SystemExit("API, recovery and demo OIDC ports must be distinct valid TCP ports")
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            try:
                listener.bind(("127.0.0.1", port))
            except OSError:
                raise SystemExit(f"required loopback port {port} is already in use; choose different ports") from None


def cleanup(args) -> None:
    root, info = load_instance(args.directory)
    project = info["project"]
    check_owned_resources(info, allow_missing=True)
    names = [f"{project}_{part}" for part in ("postgres", "media", "state")]
    if not args.remove_data:
        compose(args, "stop")
        print("persistent volumes and private instance secrets retained")
        return
    if args.confirm_project != project:
        raise SystemExit(f"destructive removal requires --confirm-project {project}")
    compose(args, "down")
    for name in names:
        exists = subprocess.run(("docker", "volume", "inspect", name), stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, check=False).returncode == 0
        if exists:
            command("docker", "volume", "rm", name)
    shutil.rmtree(root)
    print("removed verified project volumes and instance secret directory")


def provision_restore(args) -> None:
    root, info = load_instance(args.directory)
    if check_any_resource(info):
        raise SystemExit("restore provisioning requires absent project resources on the fresh host")
    inventory = info.get("backup_inventory", {})
    if set(inventory) != {"postgres", "media", "state"} or not inventory["postgres"].get("postgres_version"):
        raise SystemExit("restore provisioning requires the captured cold backup inventory")
    resolved_compose(root, info)
    if inspect_image(info["image"], info["mode"])["id"] != info["image_admission"]["id"]:
        raise SystemExit("restore image differs from captured identity")
    # Persist the fence before the first resource mutation, including partial failure.
    info["established"] = False
    info["restore_pending"] = True
    info["restore_imported"] = False
    private_write(root / "instance.json", json.dumps(info, indent=2) + "\n")
    labels = ["--label", f"volt.compose.owner-token={info['owner_token']}"]
    for store in ("postgres", "media", "state"):
        command("docker", "volume", "create", *labels,
                "--label", f"com.docker.compose.project={info['project']}",
                "--label", f"com.docker.compose.volume={store}", f"{info['project']}_{store}")
    command("docker", "network", "create", "--driver", "bridge", *labels,
            "--label", f"com.docker.compose.project={info['project']}",
            "--label", "com.docker.compose.network=application",
            "--subnet", info["subnet"], "--gateway", info["gateway"], f"{info['project']}_network")
    info["restore_pending"] = True
    private_write(root / "instance.json", json.dumps(info, indent=2) + "\n")
    print("empty owned volumes and private network provisioned; no VOLT runtime was started")


def check_any_resource(info: dict) -> bool:
    names = [*(f"{info['project']}_{part}" for part in ("postgres", "media", "state")),
             f"{info['project']}_network", f"{info['project']}-volt-1"]
    for kind, name in [("volume", n) for n in names[:3]] + [("network", names[3]), ("container", names[4])]:
        if subprocess.run(("docker", kind, "inspect", name), stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, check=False).returncode == 0:
            return True
    return False


def restore_admit(args) -> None:
    root, info = load_instance(args.directory)
    if not info.get("restore_pending") or info.get("restore_imported"):
        raise SystemExit("instance is not awaiting offline volume import")
    check_owned_resources(info, allow_missing=True)
    if subprocess.run(("docker", "container", "inspect", f"{info['project']}-volt-1"),
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        raise SystemExit("restore admission requires no runtime container")
    for store in ("postgres", "media", "state"):
        actual = volume_inventory(info, store)
        if actual != info.get("backup_inventory", {}).get(store):
            raise SystemExit(f"offline {store} import differs from captured inventory")
    if not info["backup_inventory"]["postgres"].get("postgres_version"):
        raise SystemExit("restored PostgreSQL lacks PG_VERSION")
    info["restore_imported"] = True
    private_write(root / "instance.json", json.dumps(info, indent=2) + "\n")
    print("all three offline imports match captured inventories and PostgreSQL contains PG_VERSION; runtime may now start with ingress closed")


def link_subject(args) -> None:
    root, info = load_instance(args.directory)
    files, envfile, clean_env = resolved_compose(root, info)
    if info["mode"] == "demo":
        issuer = json.loads((root / "oidc.json").read_text())["issuer"]
        subject = "volt-compose-demo-admin-subject"
        principal = "volt-compose-demo-admin"
        rationale = "Explicit labelled local demo bootstrap"
        evidence_ref = "volt-compose-demo-bootstrap"
    else:
        issuer, subject, principal = args.issuer, args.subject, args.principal or info["bootstrap_principal"]
        rationale, evidence_ref = args.rationale, args.evidence_ref
    if not issuer or not subject or not principal or not rationale or not evidence_ref:
        raise SystemExit("issuer, exact subject, principal, rationale and evidence reference are required")
    body = json.dumps({"issuer": issuer, "subject": subject, "principal_id": principal,
        "display_label": "Explicit OIDC bootstrap link", "rationale": rationale, "evidence_ref": evidence_ref})
    script = ("import json,sys,urllib.request; token=open('/run/uvm-g7-secrets/oidc_operator_secret').read().strip(); "
              "body=json.loads(sys.argv[1]); req=urllib.request.Request('http://127.0.0.1:8000/api/v1/auth/operator/links', "
              "data=json.dumps(body).encode(), headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'}); "
              "print(urllib.request.urlopen(req, timeout=10).read().decode())")
    command("docker", "compose", *files, "--env-file", str(envfile), "-p", info["project"],
            "exec", "-T", "volt", "/opt/uvm/venv/bin/python", "-c", script, body,
            env=clean_env)


def wait_until_ready(info: dict) -> None:
    name = f"{info['project']}-volt-1"
    for _ in range(60):
        result = subprocess.run(("docker", "container", "inspect", name,
                                 "--format", "{{.State.Health.Status}}"), capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip() == "healthy":
            return
        import time
        time.sleep(2)
    raise SystemExit("VOLT did not become healthy; authority initialization was not attempted")


def initialize_authority(args) -> None:
    root, info = load_instance(args.directory)
    files, envfile, clean_env = resolved_compose(root, info)
    wait_until_ready(info)
    callback = json.loads((root / "oidc.json").read_text())["callback_url"]
    origin = callback.removesuffix("/api/v1/auth/callback")
    script = r'''import json,sys,urllib.request,uuid
cookie=sys.stdin.read().strip()
if not cookie: raise SystemExit("session cookie was empty")
origin,expected=sys.argv[1:3]; base="http://127.0.0.1:8000"
def call(path,method="GET",body=None,csrf=None):
    headers={"Cookie":"uvm_session="+cookie,"Origin":origin}
    data=None
    if body is not None:
        data=json.dumps(body).encode(); headers["Content-Type"]="application/json"; headers["X-CSRF-Token"]=csrf or ""
    req=urllib.request.Request(base+path,data=data,headers=headers,method=method)
    try:
        with urllib.request.urlopen(req,timeout=15) as r: return r.status,json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e: return e.code,json.loads(e.read() or b"{}")
status,session=call("/api/v1/auth/session")
if status!=200 or session.get("principal_id")!=expected: raise SystemExit("authenticated subject does not match configured bootstrap principal")
csrf=session.get("csrf_token"); zero="00000000-0000-4000-8000-000000000000"
policy={"grants":[],"denies":[],"owner_directory":[{"owner_id":expected,"owner_type":"person","display_name":"VOLT bootstrap administrator","enabled":True}],"acceptance_material_changes":{},"exception_warning_routes":[]}
code,_=call("/api/v1/assessment/bootstrap-policy","POST",{"policy":policy},csrf)
if code not in (200,409): raise SystemExit("protected policy bootstrap was rejected")
status,catalogue=call("/api/v1/assessment/administration/catalogue")
if status!=200 or catalogue.get("caller",{}).get("principal_id")!=expected: raise SystemExit("bootstrap administrator is not linked or readable")
if catalogue.get("authority_mode")=="legacy":
    rev={"target":catalogue["policy_revision"],"policy":catalogue["policy_revision"],"authority":catalogue["authority_revision"],"identity_membership":0,"owners":0}
    body={"command_id":str(uuid.uuid4()),"target_id":zero,"membership_ids":[],"action":"native.authority.activate","expected_revisions":rev,"payload":{"mapping_revision":1,"rationale":"Initialize native authority for the explicitly admitted Compose administrator","evidence_ref":"volt-compose-authority-init"}}
    code,_=call("/api/v1/assessment/commands","POST",body,csrf)
    if code!=200: raise SystemExit("native authority activation was rejected")
status,catalogue=call("/api/v1/assessment/administration/catalogue")
grant=catalogue.get("caller",{}).get("grantable",{})
if status!=200 or catalogue.get("authority_mode")!="uvm_native_v1" or "access_group.read" not in grant.get("actions",[]): raise SystemExit("native authority readiness or scoped grant envelope is unavailable")
status,_=call("/api/v1/assessment/access-groups")
if status!=200: raise SystemExit("permission-scoped readback failed")
print(json.dumps({"authority_mode":catalogue["authority_mode"],"principal_id":expected,"permission_scoped_readback":status,"repeat_safe":True}))
'''
    cookie = getpass.getpass("Authenticated uvm_session cookie value: ")
    command("docker", "compose", *files, "--env-file", str(envfile), "-p", info["project"],
            "exec", "-T", "volt", "/opt/uvm/venv/bin/python", "-c", script,
            origin, info["bootstrap_principal"], env=clean_env, input_data=cookie + "\n")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(required=True)
    create = sub.add_parser("init")
    create.add_argument("directory")
    create.add_argument("--mode", choices=("demo", "external"), required=True)
    create.add_argument("--project", default="volt-compose")
    create.add_argument("--image", required=True, help="explicit immutable Compose-compatible candidate image; historical RC1 lacks this contract")
    create.add_argument("--external-config")
    create.add_argument("--client-secret-file")
    create.add_argument("--bootstrap-principal", help="stable principal ID to link and initialize as the first administrator")
    create.add_argument("--http-port", type=int, default=8180)
    create.add_argument("--recovery-port", type=int, default=8181)
    create.add_argument("--oidc-port", type=int, default=8190)
    create.add_argument("--allowed-hosts", default="localhost,127.0.0.1")
    create.set_defaults(fn=init)
    for name in ("start", "stop", "status"):
        item = sub.add_parser(name); item.add_argument("directory"); item.set_defaults(fn=lambda a, n=name: compose(a, "up" if n == "start" else "ps" if n == "status" else "stop"))
    remove = sub.add_parser("cleanup")
    remove.add_argument("directory"); remove.add_argument("--remove-data", action="store_true")
    remove.add_argument("--confirm-project"); remove.set_defaults(fn=cleanup)
    record = sub.add_parser("backup-record")
    record.add_argument("directory"); record.set_defaults(fn=record_backup)
    provision = sub.add_parser("restore-provision")
    provision.add_argument("directory"); provision.set_defaults(fn=provision_restore)
    admit = sub.add_parser("restore-admit")
    admit.add_argument("directory"); admit.set_defaults(fn=restore_admit)
    link = sub.add_parser("link-admin")
    link.add_argument("directory"); link.add_argument("--issuer"); link.add_argument("--subject")
    link.add_argument("--principal")
    link.add_argument("--rationale"); link.add_argument("--evidence-ref"); link.set_defaults(fn=link_subject)
    authority = sub.add_parser("initialize-authority")
    authority.add_argument("directory"); authority.set_defaults(fn=initialize_authority)
    return p


if __name__ == "__main__":
    args = parser().parse_args()
    args.fn(args)
