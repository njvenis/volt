#!/usr/bin/env python3
"""Initialize and safely operate a source-free VOLT Compose instance."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import getpass
import hashlib
import ipaddress
import json
import fcntl
import os
from pathlib import Path
import re
import secrets
import socket
import shutil
import stat
import subprocess
import sys
import uuid
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (HTTPCookieProcessor, HTTPRedirectHandler, Request,
                            build_opener)

HISTORICAL_RC1_IMAGE = "ghcr.io/njvenis/volt@sha256:c0c49bc9c38a0ea946d1868748fcaadbf9e7e79dfd50b24d2b276c83c4d18497"
SECRET_SIZES = {"uvm_db_password": 32, "ce_db_password": 32, "ce_admin_password": 32,
                "ce_secret_key": 64, "ce_credential_key": 32, "uvm_cursor_secret": 48,
                "oidc_client_secret": 48, "oidc_sync_secret": 48, "oidc_operator_secret": 48}
SUPPORTED_PLATFORMS = ("linux/amd64", "linux/arm64")


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


def atomic_private_write(path: Path, value: str | bytes) -> None:
    data = value.encode() if isinstance(value, str) else value
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def exclusive_instance_lock(root: Path):
    """Serialize host lifecycle and maintenance changes; kernel releases stale locks."""
    lock_path = root / ".install.lock"
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError:
        raise SystemExit("could not open the private instance lock") from None
    try:
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
            raise SystemExit("private instance lock permissions are unsafe")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("another VOLT lifecycle or maintenance operation is active") from None
        yield
    finally:
        os.close(fd)


def compose_env_line(name: str, value: str) -> str:
    """Quote a generated Compose dotenv value without expanding dollar signs."""
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or "\n" in value or "\r" in value:
        raise SystemExit("generated Compose environment value is malformed")
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"{name}='{escaped}'"


def compose_instance_path(root: Path, *, runtime_prepare: bool,
                          host_instance_directory: str | None) -> str:
    if not runtime_prepare:
        return str(root)
    if (not host_instance_directory or not Path(host_instance_directory).is_absolute()
            or any(c in host_instance_directory for c in ",:\n\r")):
        raise SystemExit("runtime preparation requires the exact absolute host instance path")
    return host_instance_directory


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


def demo_password_verifier(username: str, password: str, confirmation: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,63}", username):
        raise SystemExit("demo admin username must be 1-64 simple ASCII characters")
    if len(password) < 16 or len(password.encode("utf-8")) > 1024 or password != confirmation:
        raise SystemExit("demo admin password must be 16-1024 UTF-8 bytes and both entries must match")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**15, r=8, p=1,
                           dklen=32, maxmem=64 * 1024 * 1024)
    return json.dumps({"schema": "uvm.demo-credential.v1", "username": username,
        "salt": salt.hex(), "password_hash": digest.hex()}, sort_keys=True, separators=(",", ":")).encode() + b"\n"


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


def inspect_image(image: str, mode: str, expected_platform: str) -> dict:
    if not ("@sha256:" in image or re.fullmatch(r"sha256:[0-9a-f]{64}", image)):
        raise SystemExit("image must be an immutable registry digest or local sha256 image ID")
    if expected_platform not in SUPPORTED_PLATFORMS:
        raise SystemExit("platform must be one of the admitted package platforms: linux/amd64, linux/arm64")
    try:
        item = json.loads(command("docker", "image", "inspect", image, capture=True))[0]
    except (json.JSONDecodeError, IndexError) as exc:
        raise SystemExit("could not inspect the selected image") from exc
    config = item.get("Config") or {}
    labels = config.get("Labels") or {}
    os_name, arch = item.get("Os"), item.get("Architecture")
    actual_platform = f"{os_name}/{arch}"
    if actual_platform != expected_platform:
        raise SystemExit(f"selected image platform {actual_platform} does not match declared package platform {expected_platform}")
    declared_modes = set((labels.get("org.volt.oidc-deployment-modes") or "").split(","))
    required_mode = {"demo": "demo", "external": "external", "local": "local"}.get(mode)
    if required_mode is None or required_mode not in declared_modes:
        raise SystemExit("this image is not Compose-install compatible with the selected authentication mode")
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
            "source_snapshot": source_snapshot, "platform": actual_platform,
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


def validate_okta_publisher(path: Path, oidc: dict) -> tuple[dict, bytes]:
    if path.is_symlink() or not path.is_file():
        raise SystemExit("Okta publisher configuration must be a regular non-symlink file")
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise SystemExit("Okta publisher configuration must be readable JSON") from None
    required = {"schema_version", "provider_id", "org_url", "api_issuer", "api_base_url",
        "client_id", "app_id", "key_id", "private_key_file", "oidc_config_file",
        "subject_by_user_id", "group_ids", "poll_interval_seconds", "heartbeat_max_age_seconds"}
    token = r"[A-Za-z0-9._:-]{1,256}"
    if not isinstance(config, dict) or set(config) != required or config.get("schema_version") != 1:
        raise SystemExit("Okta publisher config must match schema version 1")
    if (config["provider_id"] != oidc["provider_id"]
            or config["heartbeat_max_age_seconds"] != oidc["heartbeat_max_age_seconds"]
            or not isinstance(config["group_ids"], list) or not config["group_ids"]
            or any(not isinstance(group, str) or not re.fullmatch(token, group)
                   for group in config["group_ids"])
            or len(set(config["group_ids"])) != len(config["group_ids"])
            or set(config["group_ids"]) != set(oidc["group_mappings"])):
        raise SystemExit("Okta publisher provider, heartbeat or group IDs must match the external OIDC authority config")
    if (type(config["poll_interval_seconds"]) is not int
            or type(config["heartbeat_max_age_seconds"]) is not int
            or config["poll_interval_seconds"] < 5
            or config["poll_interval_seconds"] * 3 > config["heartbeat_max_age_seconds"]):
        raise SystemExit("Okta publisher interval must leave at least three polls within the heartbeat freshness limit")
    subjects = config["subject_by_user_id"]
    if (not isinstance(subjects, dict) or not subjects
            or any(not isinstance(user, str) or not re.fullmatch(token, user)
                   or not isinstance(subject, str) or not 1 <= len(subject) <= 255
                   or any(ord(char) < 0x20 or ord(char) == 0x7f for char in subject)
                   for user, subject in subjects.items())
            or len(set(subjects.values())) != len(subjects)):
        raise SystemExit("Okta publisher requires explicit unique Okta user ID to OIDC subject mappings")
    for key in ("client_id", "app_id", "key_id"):
        if not isinstance(config[key], str) or not re.fullmatch(token, config[key]):
            raise SystemExit(f"Okta publisher {key} is invalid")
    org = config["org_url"].rstrip("/")
    parsed = urlsplit(org)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment
            or config["api_issuer"] != org + "/oauth2/v1"
            or config["api_base_url"] != org + "/api/v1"):
        raise SystemExit("Okta API issuer and base URL must be the exact org Management API origins")
    allowed_origins = {urlsplit(item).scheme + "://" + urlsplit(item).netloc
                       for item in oidc["allowed_endpoint_origins"]}
    if org not in allowed_origins:
        raise SystemExit("Okta API org origin must match an admitted OIDC provider origin")
    key_path = Path(config["private_key_file"]).expanduser()
    try:
        if key_path.is_symlink() or not key_path.is_file() or stat.S_IMODE(key_path.stat().st_mode) & 0o077:
            raise OSError
        key = key_path.read_bytes()
        if not key:
            raise OSError
    except OSError:
        raise SystemExit("Okta service private key must be a non-empty regular file with mode 0600 or stricter") from None
    config["private_key_file"] = "/run/uvm-g7-secrets/okta_service_private_key"
    config["oidc_config_file"] = "/etc/volt/oidc.json"
    return config, key


def demo_identity(principal: str | None, subject: str | None) -> tuple[str, str]:
    principal = "volt-compose-demo-admin" if principal is None else principal
    subject = "volt-compose-demo-admin-subject" if subject is None else subject
    pattern = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
    if not re.fullmatch(pattern, principal):
        raise SystemExit("demo bootstrap principal must be a stable principal ID")
    if not re.fullmatch(pattern, subject):
        raise SystemExit("demo subject must be a stable provider subject")
    return principal, subject


def local_auth_configuration(installation_id: str, secret_source_id: str,
                             public_origin: str, http_port: int, gateway: str) -> dict:
    """Build the exact version-1 local runtime file for an owned loopback install."""
    try:
        if str(uuid.UUID(installation_id)) != installation_id or str(uuid.UUID(secret_source_id)) != secret_source_id:
            raise ValueError
        origin = urlsplit(public_origin)
        if (origin.scheme != "http" or origin.hostname not in {"127.0.0.1", "localhost", "::1"}
                or origin.username or origin.password or origin.path or origin.query or origin.fragment
                or origin.port != http_port):
            raise ValueError
        gateway_address = ipaddress.ip_address(gateway)
        if not gateway_address.is_private:
            raise ValueError
    except (ValueError, TypeError):
        raise SystemExit("local mode currently requires an exact loopback HTTP origin and private Docker gateway") from None
    return {"schema_version": 1, "installation_id": installation_id,
        "public_origin": public_origin,
        "secret_source": {"kind": "encrypted_local_v1", "secret_source_id": secret_source_id,
                          "key_path": "/run/uvm-connector/local-key"},
        "bootstrap_delivery": {"kind": "private_file", "path": "/run/volt-bootstrap/capability"},
        "session_policy": {"ttl_seconds": 3600},
        "trusted_ingress": {"mode": "loopback",
            "allowed_hosts": [f"127.0.0.1:{http_port}", f"localhost:{http_port}"],
            "allowed_peer_cidrs": ["127.0.0.1/32", f"{gateway}/32"]}}


def capability_from_delivery(value: bytes, operation: str) -> str:
    purposes = {"prepare-setup": ("setup", 1800), "rotate-setup": ("setup", 1800),
        "create-account": ("enrolment", 900), "issue-enrolment": ("enrolment", 900),
        "issue-recovery": ("recovery", 900)}
    expected = purposes.get(operation)
    try:
        document = json.loads(value)
        capability = document["capability"]
        if (expected is None or not isinstance(document, dict)
                or set(document) != {"schema_version", "purpose", "capability", "expires_in_seconds"}
                or document["schema_version"] != 1 or document["purpose"] != expected[0]
                or document["expires_in_seconds"] != expected[1]
                or not isinstance(capability, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", capability)):
            raise ValueError
    except (TypeError, KeyError, ValueError, json.JSONDecodeError):
        raise SystemExit("private capability delivery document is invalid for the requested operation") from None
    return capability


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
    if args.runtime_prepare:
        compose_assets = root / "compose"
        expected_assets = {"compose.yaml", "local.yaml", "local-restore.yaml"}
        if (not root.is_dir() or root.is_symlink() or stat.S_IMODE(root.stat().st_mode) != 0o700
                or {item.name for item in root.iterdir()} != {"compose"}
                or compose_assets.is_symlink() or not compose_assets.is_dir()
                or {item.name for item in compose_assets.iterdir()} != expected_assets
                or any(item.is_symlink() or not item.is_file() for item in compose_assets.iterdir())):
            raise SystemExit("runtime preparation requires an empty private instance plus the closed Compose asset set")
    elif root.exists():
        raise SystemExit(f"refusing to initialize existing instance path: {root}")
    image = args.image
    if not image:
        raise SystemExit(f"Compose installation requires --image with an explicitly built compatible candidate; historical RC1 {HISTORICAL_RC1_IMAGE} is retained for launcher users and lacks the Compose contract")
    if args.runtime_prepare:
        if (args.mode != "local" or not args.admitted_image_id
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", args.admitted_image_id)
                or not re.fullmatch(r"[0-9a-f]{40}", args.admitted_source_revision or "")
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", args.admitted_source_snapshot or "")
                or args.admitted_version != "0.1.0-rc.4"
                or not args.network_gateway or not args.network_subnet or not args.owner_token
                or not re.fullmatch(r"[0-9a-f]{64}", args.owner_token)):
            raise SystemExit("runtime preparation requires exact local RC4 image and private network admission metadata")
        host_instance_path = compose_instance_path(root, runtime_prepare=True,
            host_instance_directory=args.host_instance_directory)
        try:
            if not ipaddress.ip_network(args.network_subnet, strict=True).is_private:
                raise ValueError
        except ValueError:
            raise SystemExit("runtime preparation requires a private Docker subnet") from None
        admitted = {"id": args.admitted_image_id, "source_revision": args.admitted_source_revision,
            "version": args.admitted_version, "source_snapshot": args.admitted_source_snapshot,
            "platform": args.platform, "registry_digests": [image]}
    else:
        check_ports_available((args.http_port, args.recovery_port, args.oidc_port))
        admitted = inspect_image(image, args.mode, args.platform)
    okta_config, okta_private_key = None, None
    local_auth = None
    if args.mode == "external":
        if args.demo_admin_username is not None:
            raise SystemExit("--demo-admin-username is available only in demo mode")
        if args.demo_subject is not None:
            raise SystemExit("--demo-subject is available only in labelled synthetic demo mode")
        oidc = validate_external(Path(args.external_config).expanduser())
        if not args.client_secret_file:
            raise SystemExit("external mode requires --client-secret-file for the configured OIDC client")
        external_client_secret = private_secret(Path(args.client_secret_file).expanduser())
        callback_host = urlsplit(oidc["callback_url"]).hostname.lower().rstrip(".")
        if callback_host not in {v.lower().rstrip(".") for v in args.allowed_hosts.split(",")}:
            raise SystemExit("external OIDC callback hostname must appear exactly in --allowed-hosts")
        if args.okta_publisher_config:
            okta_config, okta_private_key = validate_okta_publisher(
                Path(args.okta_publisher_config).expanduser(), oidc)
        else:
            okta_config, okta_private_key = None, None
    elif args.mode == "local":
        if any((args.external_config, args.client_secret_file, args.okta_publisher_config,
                args.bootstrap_principal, args.demo_subject, args.demo_admin_username)):
            raise SystemExit("local mode does not accept demo or external OIDC bootstrap arguments")
        public_origin = args.public_origin or f"http://127.0.0.1:{args.http_port}"
        args.bootstrap_principal = ""
        installation_id = str(uuid.uuid4())
        secret_source_id = str(uuid.uuid4())
        local_auth = None
        args.local_installation_id = installation_id
        args.local_secret_source_id = secret_source_id
        args.local_public_origin = public_origin
        oidc = None
        demo_credentials = None
        external_client_secret = None
    else:
        if not args.demo_admin_username:
            raise SystemExit("demo mode requires --demo-admin-username and a hidden password prompt")
        if args.okta_publisher_config:
            raise SystemExit("--okta-publisher-config is available only in external mode")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,63}", args.demo_admin_username):
            raise SystemExit("demo admin username must be 1-64 simple ASCII characters")
        password = getpass.getpass("New local demo admin password (16+ characters): ")
        confirmation = getpass.getpass("Confirm local demo admin password: ")
        demo_credentials = demo_password_verifier(args.demo_admin_username, password, confirmation)
        del password, confirmation
        external_client_secret = None
        args.bootstrap_principal, args.demo_subject = demo_identity(args.bootstrap_principal, args.demo_subject)
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
            "source_scope_ceilings": [{"source_family": "local",
                "source_account_id": "volt-local-preview", "scope_key": "all"}],
            "group_mappings": {"volt-compose-demo-admin-group": {
                "role_ids": ["00000000-0000-4000-8000-000000000002"],
                "source_scopes": [{"source_family": "local",
                    "source_account_id": "volt-local-preview", "scope_key": "all"}]}},
            "mapping_revision": 1,
            "session_ttl_seconds": 3600, "heartbeat_max_age_seconds": 120}
    if args.mode == "external":
        if not args.bootstrap_principal or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", args.bootstrap_principal):
            raise SystemExit("external mode requires --bootstrap-principal with a stable principal ID")
    project = re.sub(r"[^a-z0-9_-]", "", args.project.lower())
    if not project or not project[0].isalpha():
        raise SystemExit("project must start with a letter and contain only letters, numbers, '-' or '_'")
    hosts = allowed_host_names(args.allowed_hosts)
    if args.runtime_prepare:
        subnet, gateway = args.network_subnet, args.network_gateway
    else:
        for kind, name in [("volume", f"{project}_{part}") for part in ("postgres", "media", "state")]+[("network", f"{project}_network")]:
            if subprocess.run(("docker", kind, "inspect", name), stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, check=False).returncode == 0:
                raise SystemExit(f"refusing to adopt existing Docker resource {name}; choose a new project name")
        subnet, gateway = choose_network()
    if args.mode == "local":
        local_auth = local_auth_configuration(args.local_installation_id,
            args.local_secret_source_id, args.local_public_origin, args.http_port, gateway)
    if args.runtime_prepare:
        if stat.S_IMODE(root.stat().st_mode) != 0o700:
            raise SystemExit("runtime-prepared instance directory must have mode 0700")
    else:
        root.mkdir(mode=0o700, parents=True)
    secrets_dir = root / "secrets"
    secrets_dir.mkdir(mode=0o700)
    for name, size in SECRET_SIZES.items():
        private_write(secrets_dir / name, secrets.token_urlsafe(size) + "\n")
    if args.mode == "external":
        private_write(secrets_dir / "oidc_client_secret", external_client_secret)
        if okta_config is not None:
            private_write(secrets_dir / "okta_service_private_key", okta_private_key)
            private_write(root / "okta-publisher.json",
                          json.dumps(okta_config, sort_keys=True, separators=(",", ":")) + "\n")
    elif args.mode == "demo":
        private_write(secrets_dir / "demo_admin_credentials", demo_credentials)
    else:
        private_write(secrets_dir / "local-auth-key", secrets.token_bytes(32))
        (secrets_dir / "bootstrap-delivery").mkdir(mode=0o700)
        private_write(root / "local-auth.json",
                      json.dumps(local_auth, sort_keys=True, separators=(",", ":")) + "\n")
    make_tls(secrets_dir)
    if oidc is not None:
        private_write(root / "oidc.json", json.dumps(oidc, separators=(",", ":")) + "\n")
    else:
        # The base Compose file mounts this path for legacy modes. Local mode
        # clears UVM_OIDC_CONFIG_FILE and never reads the inert compatibility file.
        private_write(root / "oidc.json", "{}\n")
    compose_root = Path(args.runtime_compose_directory).resolve() if args.runtime_prepare else Path(__file__).resolve().parent
    owner_token = args.owner_token if args.runtime_prepare else secrets.token_hex(32)
    scopes = oidc.get("source_scope_ceilings", []) if oidc else []
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
    if local_auth is not None:
        envelope = {"contract_version": 2,
            "actions": ["policy.read", "access_group.read", "ownership.team.read", "ownership.team.manage",
                        "connector.read", "connector.configure", "connector.secret.manage",
                        "assessment.read", "audit.read"],
            "target_scope": {"group_ids": [], "source_families": [], "environments": [],
                             "service_ids": [], "membership_mode": "explicit"},
            "source_scopes": [],
            "deployment_targets": [local_auth["installation_id"]],
            "connector_targets": [], "source_read_targets": [],
            "limits": {"maximum_acceptance_days": None, "maximum_severity": None,
                "whole_group_confirmation": False, "allowed_environments": [], "allowed_service_ids": [],
                "allowed_sla_clock_bases": [], "allowed_sla_severities": [], "allowed_sla_start_sources": [],
                "maximum_sla_duration_seconds": None, "allow_sla_backfill": False,
                "maximum_deadline_extension_seconds": None, "allowed_identity_scalar_fields": {}},
            "separation_of_duties": {"approval_requires_distinct_actor": True,
                "prohibit_requester_approval": True, "required_approver_count": 1,
                "prohibited_action_pairs": []}}
    env_values = (
        ("VOLT_PROJECT", project),
        ("VOLT_INSTANCE_DIR", host_instance_path if args.runtime_prepare else str(root)),
        ("VOLT_IMAGE", image),
        ("VOLT_AUTH_MODE", "local" if args.mode == "local" else "oidc"),
        ("VOLT_LOCAL_SECRET_SOURCE_ID", local_auth["secret_source"]["secret_source_id"] if local_auth else ""),
        ("VOLT_IMAGE_ID", admitted["id"]), ("VOLT_PLATFORM", admitted["platform"]),
        ("VOLT_OKTA_PUBLISHER_CONFIG_FILE", "/run/uvm-g7-secrets/okta-publisher.json" if okta_config else ""),
        ("VOLT_DEMO_ADMIN_SUBJECT", args.demo_subject or ""),
        ("VOLT_BOOTSTRAP_PRINCIPAL", args.bootstrap_principal),
        ("VOLT_NATIVE_GRANTABLE_ENVELOPE", json.dumps(envelope, separators=(",", ":"))),
        ("VOLT_OWNER_TOKEN", owner_token), ("VOLT_SUBNET", subnet), ("VOLT_GATEWAY", gateway),
        ("VOLT_HTTP_PORT", str(args.http_port)), ("VOLT_RECOVERY_PORT", str(args.recovery_port)),
        ("VOLT_OIDC_PORT", str(args.oidc_port)), ("VOLT_ALLOWED_HOSTS", hosts),
    )
    env = "\n".join(compose_env_line(name, value) for name, value in env_values) + "\n"
    private_write(root / ".env", env)
    metadata = {"format_version": 1, "project": project, "mode": args.mode, "image": image,
                "image_admission": admitted, "oidc_config_sha256": hashlib.sha256((root / "oidc.json").read_bytes()).hexdigest(),
                "compose_directory": str(compose_root), "owner_token": owner_token,
                "bootstrap_principal": args.bootstrap_principal,
                "platform": admitted["platform"],
                "demo_admin_subject": args.demo_subject if args.mode == "demo" else None,
                "demo_admin_username": args.demo_admin_username if args.mode == "demo" else None,
                "okta_publisher_config_sha256": hashlib.sha256((root / "okta-publisher.json").read_bytes()).hexdigest()
                    if okta_config else None,
                "ports": [args.http_port, args.recovery_port, args.oidc_port],
                "subnet": subnet, "gateway": gateway, "established": False, "initialized": True}
    if local_auth is not None:
        metadata["installation_id"] = local_auth["installation_id"]
        metadata["local_recovery_journal_id"] = str(uuid.uuid4())
        metadata["local_auth_config_sha256"] = hashlib.sha256((root / "local-auth.json").read_bytes()).hexdigest()
    metadata["env_sha256"] = hashlib.sha256((root / ".env").read_bytes()).hexdigest()
    private_write(root / "instance.json", json.dumps(metadata, indent=2) + "\n")
    private_write(root / ".project", project + "\n")
    private_write(root / ".owner-token", owner_token + "\n")
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
    if (metadata.get("mode") != "local"
            and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", metadata.get("bootstrap_principal", ""))):
        raise SystemExit("instance bootstrap principal metadata is invalid")
    if (metadata.get("platform") not in SUPPORTED_PLATFORMS
            or (metadata.get("image_admission") or {}).get("platform") != metadata.get("platform")):
        raise SystemExit("instance platform metadata does not match its admitted image")
    if (metadata.get("mode") == "demo" and not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", metadata.get("demo_admin_subject", ""))):
        raise SystemExit("instance demo subject metadata is invalid")
    if metadata.get("mode") == "demo":
        credential = root / "secrets" / "demo_admin_credentials"
        if (credential.is_symlink() or not credential.is_file()
                or stat.S_IMODE(credential.stat().st_mode) != 0o600):
            raise SystemExit("demo admin credential verifier is missing or not private")
        try:
            value = json.loads(credential.read_text())
        except (OSError, json.JSONDecodeError):
            raise SystemExit("demo admin credential verifier is invalid") from None
        if (not isinstance(value, dict) or value.get("schema") != "uvm.demo-credential.v1"
                or value.get("username") != metadata.get("demo_admin_username")
                or not re.fullmatch(r"[0-9a-f]{32}", value.get("salt", ""))
                or not re.fullmatch(r"[0-9a-f]{64}", value.get("password_hash", ""))):
            raise SystemExit("demo admin credential verifier does not match initialized account")
    for name in (*SECRET_SIZES, "recovery-server.crt", "recovery-server.key", "recovery-client.crt",
                 "recovery-client.key", "recovery-ca.crt"):
        secret = root / "secrets" / name
        if secret.is_symlink() or not secret.is_file() or not secret.read_bytes().strip():
            raise SystemExit("instance secret or recovery identity file is missing, empty or not regular")
    actual = hashlib.sha256((root / "oidc.json").read_bytes()).hexdigest()
    if actual != metadata.get("oidc_config_sha256"):
        raise SystemExit("OIDC config changed after initialization; use explicit reconfigure after review")
    if metadata.get("mode") == "local":
        config_path = root / "local-auth.json"
        local_key = root / "secrets" / "local-auth-key"
        delivery = root / "secrets" / "bootstrap-delivery"
        if (config_path.is_symlink() or not config_path.is_file()
                or stat.S_IMODE(config_path.stat().st_mode) != 0o600
                or config_path.stat().st_uid != os.getuid()
                or local_key.is_symlink() or not local_key.is_file()
                or stat.S_IMODE(local_key.stat().st_mode) != 0o600
                or local_key.stat().st_uid != os.getuid()
                or len(local_key.read_bytes()) != 32
                or delivery.is_symlink() or not delivery.is_dir()
                or stat.S_IMODE(delivery.stat().st_mode) != 0o700
                or delivery.stat().st_uid != os.getuid()):
            raise SystemExit("local auth configuration, encryption key or bootstrap delivery directory is missing or unsafe")
        recovery = metadata.get("local_recovery_custody")
        journal_id = metadata.get("local_recovery_journal_id")
        try:
            recovery_valid = (isinstance(recovery, dict)
                and set(recovery) == {"schema_version", "profile", "installation_id", "journal_id",
                                     "restore_generation", "recovery_epoch_id"}
                and type(recovery["schema_version"]) is int and recovery["schema_version"] == 1
                and recovery["profile"] == "volt_local_recovery_v1"
                and recovery["installation_id"] == metadata["installation_id"]
                and recovery["journal_id"] == journal_id
                and str(uuid.UUID(journal_id)) == journal_id
                and type(recovery["restore_generation"]) is int
                and recovery["restore_generation"] >= 0
                and ((recovery["restore_generation"] == 0 and recovery["recovery_epoch_id"] is None)
                     or (recovery["restore_generation"] > 0
                         and str(uuid.UUID(recovery["recovery_epoch_id"])) == recovery["recovery_epoch_id"])))
        except (KeyError, TypeError, ValueError, AttributeError):
            recovery_valid = False
        if not recovery_valid:
            raise SystemExit("local recovery custody journal is missing or inconsistent")
        recovery_inventory = {
            "local-recovery.json": 0o600,
            "secrets/local-recovery-runtime/issuer.key": 0o600,
            "secrets/local-recovery-runtime/issuer.pub": 0o600,
            "secrets/local-recovery-runtime/operator.pub": 0o600,
            "secrets/local-recovery-runtime/material.key": 0o600,
            "secrets/local-recovery-authority/operator.key": 0o600,
            "secrets/local-recovery-authority/operator.pub": 0o600,
            "secrets/local-recovery-authority/issuer.pub": 0o600,
            "secrets/local-recovery-authority/host.json": 0o600,
            "secrets/local-restore-fence/fence.json": 0o600,
        }
        for relative, mode in recovery_inventory.items():
            path = root / relative
            if (path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != mode
                    or path.stat().st_uid != os.getuid()):
                raise SystemExit(f"local recovery custody file is missing or unsafe: {relative}")
        for relative in ("secrets/local-recovery-runtime", "secrets/local-recovery-authority",
                         "secrets/local-restore-fence"):
            path = root / relative
            if (path.is_symlink() or not path.is_dir() or stat.S_IMODE(path.stat().st_mode) != 0o700
                    or path.stat().st_uid != os.getuid()):
                raise SystemExit(f"local recovery custody directory is missing or unsafe: {relative}")
        try:
            local = json.loads(config_path.read_text())
            source = local["secret_source"]
            capability = local["bootstrap_delivery"]
            url = urlsplit(local["public_origin"])
            port = metadata["ports"][0]
            if (set(local) != {"schema_version", "installation_id", "public_origin", "secret_source",
                               "bootstrap_delivery", "session_policy", "trusted_ingress"}
                    or local["schema_version"] != 1
                    or str(uuid.UUID(local["installation_id"])) != local["installation_id"]
                    or local["installation_id"] != metadata.get("installation_id")
                    or hashlib.sha256(config_path.read_bytes()).hexdigest() != metadata.get("local_auth_config_sha256")
                    or source != {"kind": "encrypted_local_v1", "secret_source_id":
                                  source["secret_source_id"], "key_path": "/run/uvm-connector/local-key"}
                    or str(uuid.UUID(source["secret_source_id"])) != source["secret_source_id"]
                    or capability != {"kind": "private_file", "path": "/run/volt-bootstrap/capability"}
                    or local["session_policy"] != {"ttl_seconds": 3600}
                    or local["trusted_ingress"] != {"mode": "loopback", "allowed_hosts":
                        [f"127.0.0.1:{port}", f"localhost:{port}"], "allowed_peer_cidrs":
                        ["127.0.0.1/32", f"{metadata['gateway']}/32"]}
                    or url.scheme != "http" or url.hostname not in {"127.0.0.1", "localhost", "::1"}
                    or url.port != port or url.path or url.query or url.fragment):
                raise ValueError
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise SystemExit("local auth configuration does not match its private instance contract") from None
    publisher_digest = metadata.get("okta_publisher_config_sha256")
    if publisher_digest is not None:
        config_file = root / "okta-publisher.json"
        private_key = root / "secrets" / "okta_service_private_key"
        if (metadata.get("mode") != "external" or config_file.is_symlink() or not config_file.is_file()
                or private_key.is_symlink() or not private_key.is_file()
                or stat.S_IMODE(private_key.stat().st_mode) != 0o600
                or hashlib.sha256(config_file.read_bytes()).hexdigest() != publisher_digest):
            raise SystemExit("Okta publisher config or private key changed after initialization")
    return root, metadata


def compose_environment() -> dict[str, str]:
    """Keep Compose interpolation owned by the admitted instance .env only."""
    return {k: v for k, v in os.environ.items()
            if not k.startswith(("VOLT_", "COMPOSE_")) and k != "ENV"}


def compose_files(info: dict) -> list[str]:
    files = ["-f", str(Path(info["compose_directory"]) / "compose.yaml")]
    if info["mode"] == "local":
        files += ["-f", str(Path(info["compose_directory"]) / "local.yaml")]
        if (info.get("restore_pending") and info.get("restore_imported")
                and not (info.get("restore_capabilities_revoked")
                         and info.get("restore_sessions_revoked"))):
            files += ["-f", str(Path(info["compose_directory"]) / "local-restore.yaml")]
    elif info["mode"] == "demo":
        files += ["-f", str(Path(info["compose_directory"]) / "demo.yaml")]
    elif info.get("okta_publisher_config_sha256") is not None:
        files += ["-f", str(Path(info["compose_directory"]) / "okta-publisher.yaml")]
    return files


def resolved_compose(root: Path, info: dict):
    files = compose_files(info)
    identity_secrets = identity_secret_sources(root, info)
    for name, source in identity_secrets.items():
        if (source.is_symlink() or not source.is_file() or not source.read_bytes().strip()
                or stat.S_IMODE(source.stat().st_mode) != 0o600):
            raise SystemExit(f"required private identity secret is missing or unsafe: {name}")
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
    if info["mode"] == "local":
        expected_mounts.update({
            "/run/secrets/local-auth.json": str(root / "local-auth.json"),
            "/run/secrets/local-auth-key": str(root / "secrets" / "local-auth-key"),
            "/run/volt-bootstrap": str(root / "secrets" / "bootstrap-delivery"),
            "/run/secrets/local-recovery.json": str(root / "local-recovery.json"),
            "/run/secrets/local-recovery-issuer.key": str(root / "secrets/local-recovery-runtime/issuer.key"),
            "/run/secrets/local-recovery-issuer.pub": str(root / "secrets/local-recovery-runtime/issuer.pub"),
            "/run/secrets/local-recovery-operator.pub": str(root / "secrets/local-recovery-runtime/operator.pub"),
            "/run/secrets/local-recovery-material.key": str(root / "secrets/local-recovery-runtime/material.key"),
            "/run/secrets/local-recovery-fence": str(root / "secrets/local-restore-fence"),
        })
    volume_names = resolved.get("volumes", {})
    validate_identity_secret_mounts(resolved, service, identity_secrets, info)
    actual_mounts = {item.get("target"): (volume_names.get(item.get("source"), {}).get("name", item.get("source"))
                                           if item.get("type") == "volume" else item.get("source", "").replace("$$", "$"))
                     for item in service.get("volumes", [])}
    if info["mode"] == "local":
        mounts_by_target = {item.get("target"): item for item in service.get("volumes", [])}
        expected_access = {"/run/secrets/local-auth.json": True,
            "/run/secrets/local-auth-key": True,
            "/run/volt-bootstrap": False,
            "/run/secrets/local-recovery.json": True,
            "/run/secrets/local-recovery-issuer.key": True,
            "/run/secrets/local-recovery-issuer.pub": True,
            "/run/secrets/local-recovery-operator.pub": True,
            "/run/secrets/local-recovery-material.key": True,
            "/run/secrets/local-recovery-fence": True}
        environment = service.get("environment", {})
        local_source = json.loads((root / "local-auth.json").read_text())["secret_source"]["secret_source_id"]
        if (any(bool(mounts_by_target.get(target, {}).get("read_only")) != read_only
                    for target, read_only in expected_access.items())
                or environment.get("UVM_AUTH_MODE") != "local"
                or environment.get("UVM_OIDC_DEPLOYMENT_MODE") != "local"
                or environment.get("UVM_LOCAL_AUTH_CONFIG_FILE") != "/etc/volt/local-auth.json"
                or environment.get("UVM_OIDC_CONFIG_FILE") != ""
                or environment.get("UVM_CONNECTOR_LOCAL_KEY_ID") != local_source
                or environment.get("UVM_CONNECTOR_LOCAL_KEY_FILE") != "/run/secrets/local-auth-key"
                or environment.get("UVM_LOCAL_RECOVERY_CONFIG_FILE") != "/etc/volt/local-recovery.json"
                or environment.get("UVM_SCANNER_EVIDENCE_DIR") != "/opt/uvm/state/scanner-evidence"):
            raise SystemExit("local Compose auth mode or private-file access differs from its admitted config")
    labels = service.get("labels", {})
    if (service.get("image") != info["image"] or service.get("platform") != info["platform"]
            or actual_mounts != expected_mounts or
            resolved.get("networks", {}).get("application", {}).get("name") != f"{info['project']}_network" or
            labels.get("volt.compose.owner-token") != info["owner_token"] or
            resolved.get("volumes", {}).get("postgres", {}).get("name") != f"{info['project']}_postgres" or
            resolved.get("volumes", {}).get("media", {}).get("name") != f"{info['project']}_media" or
            resolved.get("volumes", {}).get("state", {}).get("name") != f"{info['project']}_state"):
        raise SystemExit("resolved Compose image, platform, mounts, network, volumes or ownership differ from admitted instance metadata")
    return files, envfile, clean_env


def identity_secret_sources(root: Path, info: dict) -> dict[str, Path]:
    """Return only mode-authorized identity files that Compose may mount."""
    if info.get("mode") == "demo":
        if info.get("okta_publisher_config_sha256") is not None:
            raise SystemExit("demo mode cannot admit external Okta publisher secrets")
        return {"demo-admin-credentials": root / "secrets" / "demo_admin_credentials"}
    if info.get("mode") == "local":
        return {}
    if info.get("mode") != "external":
        raise SystemExit("instance identity mode is unsupported")
    if info.get("okta_publisher_config_sha256") is None:
        return {}
    return {"okta-publisher.json": root / "okta-publisher.json",
        "okta_service_private_key": root / "secrets" / "okta_service_private_key"}


def validate_identity_secret_mounts(resolved: dict, service: dict,
                                    expected_sources: dict[str, Path], info: dict) -> None:
    refs = service.get("secrets", [])
    mounts = {(item.get("source"), item.get("target", item.get("source")))
        for item in refs if isinstance(item, dict)}
    definitions = resolved.get("secrets", {})
    identity_names = {"demo-admin-credentials", "okta-publisher.json", "okta_service_private_key"}
    expected_names = set(expected_sources)
    defined_identity = set(definitions) & identity_names
    mounted_identity = {source for source, _target in mounts if source in identity_names}
    mounted_identity |= {target.rsplit("/", 1)[-1] for _source, target in mounts
        if target.rsplit("/", 1)[-1] in identity_names}
    if defined_identity != expected_names or mounted_identity != expected_names:
        raise SystemExit("resolved Compose identity secrets differ from the exact admitted deployment mode")
    for name, path in expected_sources.items():
        definition = definitions.get(name)
        targets = {name, f"/run/secrets/{name}"}
        if (not any(source == name and target in targets for source, target in mounts)
                or not isinstance(definition, dict)
                or Path(definition.get("file", "")).resolve() != path.resolve()):
            raise SystemExit(f"resolved Compose identity secret mount is missing or mismatched: {name}")


def compose(args, action: str) -> None:
    root, info = load_instance(args.directory)
    with exclusive_instance_lock(root):
        compose_loaded(root, info, action)


def compose_loaded(root: Path, info: dict, action: str) -> None:
    if action == "up" and info.get("restore_pending") and not info.get("restore_imported"):
        raise SystemExit("offline restore volumes must be imported and admitted with restore-admit before any runtime starts")
    files, envfile, clean_env = resolved_compose(root, info)
    if action == "up":
        admitted = inspect_image(info["image"], info["mode"], info["platform"])
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
        if (info.get("mode") == "local" and info.get("restore_pending")
                and info.get("restore_imported") and not info.get("restore_sessions_revoked")):
            # The reviewed backend checkpoint currently exposes capability
            # revocation but does not guarantee restored-session revocation.
            # Keep the restore overlay selected and refuse ingress until that
            # missing backend guarantee is accepted and wired here.
            if not info.get("restore_capabilities_revoked"):
                wait_until_ready(info)
                revoke_restored_local_capabilities(root, info, files, envfile, clean_env)
                info["restore_capabilities_revoked"] = True
                private_write(root / "instance.json", json.dumps(info, indent=2) + "\n")
            raise SystemExit("restored local sessions lack backend-confirmed revocation; ingress remains unpublished")
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


def revoke_restored_local_capabilities(root: Path, info: dict, files: list[str],
                                       envfile: Path, clean_env: dict[str, str]) -> None:
    """Revoke restored sessions and capabilities before publishing local ingress."""
    argv = ["docker", "compose", *files, "--env-file", str(envfile), "-p", info["project"],
            "exec", "-T", "--user", "0:0", "volt", "/opt/uvm/venv/bin/python",
            "-m", "uvm.auth.maintenance", "revoke-capabilities",
            "--config", "/etc/volt/local-auth.json"]
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, text=True, env=clean_env)
    if result.returncode:
        raise SystemExit("restored local capabilities could not be revoked; ingress remains unpublished")


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
    if info.get("restore_pending"):
        raise SystemExit("this instance already has a restore fence; refusing to create another epoch")
    if check_any_resource(info):
        raise SystemExit("restore provisioning requires absent project resources on the fresh host")
    inventory = info.get("backup_inventory", {})
    if set(inventory) != {"postgres", "media", "state"} or not inventory["postgres"].get("postgres_version"):
        raise SystemExit("restore provisioning requires the captured cold backup inventory")
    resolved_compose(root, info)
    if inspect_image(info["image"], info["mode"], info["platform"])["id"] != info["image_admission"]["id"]:
        raise SystemExit("restore image differs from captured identity")
    # Persist the fence before the first resource mutation, including partial failure.
    info["established"] = False
    info["restore_pending"] = True
    info["restore_imported"] = False
    info["restore_capabilities_revoked"] = False
    info["restore_sessions_revoked"] = False
    if info["mode"] == "local":
        prior = info["local_recovery_custody"]
        next_custody = {**prior, "restore_generation": prior["restore_generation"] + 1,
                        "recovery_epoch_id": str(uuid.uuid4())}
        fence = root / "secrets/local-restore-fence/fence.json"
        atomic_private_write(fence, json.dumps(next_custody, sort_keys=True,
                                                separators=(",", ":")) + "\n")
        info["local_recovery_custody"] = next_custody
    atomic_private_write(root / "instance.json", json.dumps(info, indent=2) + "\n")
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
    atomic_private_write(root / "instance.json", json.dumps(info, indent=2) + "\n")
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
        oidc = json.loads((root / "oidc.json").read_text())
        issuer = oidc["issuer"]
        subject = info["demo_admin_subject"]
        principal = info["bootstrap_principal"]
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


def local_maintenance(args) -> None:
    root, info = load_instance(args.directory)
    with exclusive_instance_lock(root):
        local_maintenance_loaded(args, root, info)


def local_maintenance_loaded(args, root: Path, info: dict) -> None:
    if info.get("mode") != "local":
        raise SystemExit("local account maintenance requires a local-auth instance")
    files, envfile, clean_env = resolved_compose(root, info)
    wait_until_ready(info)
    operation = args.operation
    allowed = {"prepare-setup", "rotate-setup", "create-account", "issue-enrolment",
               "issue-recovery", "disable-account", "revoke-capabilities"}
    if operation not in allowed:
        raise SystemExit("unsupported local maintenance operation")
    argv = ["docker", "compose", *files, "--env-file", str(envfile), "-p", info["project"],
            # The delivered config and connector key are uvm-owned 0600 inside
            # the container. The host account's numeric uid is unrelated and
            # cannot safely access either file.
            "exec", "-T", "--user", "0:0", "volt",
            "/opt/uvm/venv/bin/python", "-m", "uvm.auth.maintenance",
            operation, "--config", "/etc/volt/local-auth.json"]
    if args.username is not None:
        argv += ["--username", args.username]
    if args.display_name is not None:
        argv += ["--display-name", args.display_name]
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, text=True, env=clean_env)
    if result.returncode:
        raise SystemExit("local maintenance operation failed; inspect redacted application status")
    if operation in {"prepare-setup", "rotate-setup", "create-account", "issue-enrolment", "issue-recovery"}:
        show_local_capability(root, info, unattended=args.unattended, purpose=operation)


def show_local_capability(root: Path, info: dict, *, unattended: bool, purpose: str = "setup") -> None:
    files, envfile, clean_env = resolved_compose(root, info)
    delivered = subprocess.run(("docker", "compose", *files, "--env-file", str(envfile), "-p", info["project"],
        "exec", "-T", "--user", "0:0", "volt", "cat", "/run/volt-bootstrap/capability"),
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=clean_env, check=False)
    if delivered.returncode:
        raise SystemExit("private capability delivery file is unavailable")
    value = capability_from_delivery(delivered.stdout, purpose)
    path = root / "secrets" / "bootstrap-capability-output"
    atomic_private_write(path, value + "\n")
    config = json.loads((root / "local-auth.json").read_text())
    if unattended or not (sys.stdin.isatty() and sys.stdout.isatty()):
        print(f"capability_file={path}")
        return
    if purpose in {"prepare-setup", "rotate-setup", "setup"}:
        print(f"Setup URL: {config['public_origin']}/")
    print(f"One-use {purpose} capability (private; do not paste into logs): {value}")


def show_setup_capability(args) -> None:
    root, info = load_instance(args.directory)
    if info.get("mode") != "local":
        raise SystemExit("setup capability display requires a local-auth instance")
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise SystemExit("setup capability display requires a controlling terminal")
    show_local_capability(root, info, unattended=False)


def host_validate(args) -> None:
    """Validate instance files inside the admitted runtime for the POSIX launcher."""
    root, info = load_instance(args.directory)
    if info.get("mode") != "local" or info.get("image") != args.image:
        raise SystemExit("instance mode or immutable runtime image differs from this signed installer")
    if (info.get("image_admission", {}).get("version") != "0.1.0-rc.4"
            or info.get("platform") not in SUPPORTED_PLATFORMS):
        raise SystemExit("instance runtime version or platform is not admitted by this installer")
    print(f"project={info['project']}\nowner_token={info['owner_token']}\nmode={info['mode']}\nplatform={info['platform']}\nhttp_port={info['ports'][0]}"
          f"\nrestore_pending={int(bool(info.get('restore_pending')))}"
          f"\nrestore_imported={int(bool(info.get('restore_imported')))}"
          f"\nrestore_capabilities_revoked={int(bool(info.get('restore_capabilities_revoked')))}"
          f"\nrestore_sessions_revoked={int(bool(info.get('restore_sessions_revoked')))}")


def extract_capability(args) -> None:
    root = Path(args.directory)
    if (root.is_symlink() or not root.is_dir() or stat.S_IMODE(root.stat().st_mode) != 0o700):
        raise SystemExit("private instance directory is unsafe")
    secrets_dir = root / "secrets"
    if (secrets_dir.is_symlink() or not secrets_dir.is_dir()
            or stat.S_IMODE(secrets_dir.stat().st_mode) != 0o700):
        raise SystemExit("private secret directory is unsafe")
    document = root / "secrets" / "bootstrap-capability-document.json"
    output = root / "secrets" / "bootstrap-capability-output"
    if (document.is_symlink() or not document.is_file()
            or stat.S_IMODE(document.stat().st_mode) != 0o600
            or document.stat().st_size > 4096):
        raise SystemExit("private capability delivery document is missing or unsafe")
    value = capability_from_delivery(document.read_bytes(), args.operation)
    atomic_private_write(output, value + "\n")
    print("capability-ready=1")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(required=True)
    create = sub.add_parser("init")
    create.add_argument("directory")
    create.add_argument("--mode", choices=("demo", "external", "local"), required=True)
    create.add_argument("--project", default="volt-compose")
    create.add_argument("--image", required=True, help="explicit immutable Compose-compatible candidate image; historical RC1 lacks this contract")
    create.add_argument("--platform", choices=SUPPORTED_PLATFORMS, required=True,
                        help="platform declared by the verified package manifest; must match Docker image inspection")
    create.add_argument("--external-config")
    create.add_argument("--client-secret-file")
    create.add_argument("--okta-publisher-config", help="optional Okta trusted membership publisher config (external mode only)")
    create.add_argument("--bootstrap-principal", help="stable principal ID to link and initialize as the first administrator")
    create.add_argument("--demo-subject", help="stable subject ID for the synthetic local demo administrator")
    create.add_argument("--demo-admin-username", help="required named local demo login; password is entered through a hidden prompt")
    create.add_argument("--http-port", type=int, default=8180)
    create.add_argument("--recovery-port", type=int, default=8181)
    create.add_argument("--oidc-port", type=int, default=8190)
    create.add_argument("--allowed-hosts", default="localhost,127.0.0.1")
    create.add_argument("--public-origin",
                        help="exact local browser origin; local mode defaults to its loopback HTTP port")
    create.add_argument("--runtime-prepare", action="store_true",
                        help=argparse.SUPPRESS)
    create.add_argument("--admitted-image-id", help=argparse.SUPPRESS)
    create.add_argument("--admitted-source-revision", help=argparse.SUPPRESS)
    create.add_argument("--admitted-source-snapshot", help=argparse.SUPPRESS)
    create.add_argument("--admitted-version", help=argparse.SUPPRESS)
    create.add_argument("--network-gateway", help=argparse.SUPPRESS)
    create.add_argument("--network-subnet", help=argparse.SUPPRESS)
    create.add_argument("--owner-token", help=argparse.SUPPRESS)
    create.add_argument("--runtime-compose-directory", help=argparse.SUPPRESS)
    create.add_argument("--host-instance-directory", help=argparse.SUPPRESS)
    create.set_defaults(fn=init)
    validate = sub.add_parser("host-validate")
    validate.add_argument("directory")
    validate.add_argument("--image", required=True)
    validate.set_defaults(fn=host_validate)
    extract = sub.add_parser("extract-capability")
    extract.add_argument("directory")
    extract.add_argument("--operation", choices=("prepare-setup", "rotate-setup", "create-account",
        "issue-enrolment", "issue-recovery"), required=True)
    extract.set_defaults(fn=extract_capability)
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
    for operation in ("prepare-setup", "rotate-setup", "create-account", "issue-enrolment",
                      "issue-recovery", "disable-account", "revoke-capabilities"):
        item = sub.add_parser(operation)
        item.add_argument("directory")
        item.add_argument("--username")
        item.add_argument("--display-name")
        item.add_argument("--unattended", action="store_true",
                          help="leave any new capability in the private delivery file and print only its path")
        item.set_defaults(fn=local_maintenance, operation=operation)
    show_capability = sub.add_parser("show-setup-capability")
    show_capability.add_argument("directory")
    show_capability.set_defaults(fn=show_setup_capability)
    return p


if __name__ == "__main__":
    args = parser().parse_args()
    args.fn(args)
