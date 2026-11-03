#!/usr/bin/env python3
"""Manage a private, loopback-only VOLT G7 local preview container."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
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
    metadata = {"instance": args.instance, "container": f"volt-g7-preview-{args.instance}",
        "volumes": {part: f"volt-g7-preview-{args.instance}-{part}" for part in ("postgres", "media", "state")},
        "api_port": api_port, "oidc_port": oidc_port, "secrets_dir": str(secrets_dir),
        "source_revision": run("git", "rev-parse", "HEAD", capture=True), "source_status": "clean"}
    (root / "instance.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    (root / "instance.json").chmod(0o600)
    print(f"initialized={root}")


def load(instance: str) -> tuple[Path, dict]:
    root = state_dir(instance)
    try:
        return root, json.loads((root / "instance.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"instance is not initialized: {instance}") from exc


def start(args) -> None:
    root, info = load(args.instance)
    current = run("git", "rev-parse", "HEAD", capture=True)
    if current != info["source_revision"] or run("git", "status", "--porcelain", capture=True):
        raise SystemExit("source revision changed after init; destroy and reinitialize against a committed clean revision")
    image = args.image or f"volt:preview-{info['source_revision']}"
    run("docker", "build", "--label", f"org.opencontainers.image.revision={info['source_revision']}",
        "--label", "org.opencontainers.image.version=local-preview", "-f", "Dockerfile.g7", "-t", image, ".")
    container = info["container"]
    existing = run("docker", "ps", "-a", "--filter", f"name={container}", "--format", "{{.Names}}", capture=True)
    if container in existing.splitlines():
        raise SystemExit(f"owned container already exists; use restart or stop first: {container}")
    for name in info["volumes"].values():
        run("docker", "volume", "create", "--label", f"volt.g7-preview.instance={args.instance}", name)
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
        "UVM_NATIVE_GRANTABLE_ENVELOPE": json.dumps({
            "actions": ["access_group.read", "ownership.team.read", "ownership.team.manage"],
            "target_scope": {"group_ids": ["*"], "source_families": ["local"],
                "environments": ["*"], "service_ids": ["*"], "membership_mode": "all_current"},
            "source_scopes": [{"source_family": "local", "source_account_id": "volt-local-preview",
                "scope_key": "all"}],
            "limits": {"maximum_acceptance_days": None, "maximum_severity": None,
                "whole_group_confirmation": False, "allowed_environments": [], "allowed_service_ids": [],
                "allowed_sla_clock_bases": [], "allowed_sla_severities": [], "allowed_sla_start_sources": [],
                "maximum_sla_duration_seconds": None, "allow_sla_backfill": False,
                "maximum_deadline_extension_seconds": None, "allowed_identity_scalar_fields": {}},
            "separation_of_duties": {"approval_requires_distinct_actor": True,
                "prohibit_requester_approval": True, "required_approver_count": 1,
                "prohibited_action_pairs": []}}, separators=(",", ":")),
        "UVM_G7_RECOVERY_TLS_CERT_FILE": "/run/uvm-g7-secrets/recovery-server.crt",
        "UVM_G7_RECOVERY_TLS_KEY_FILE": "/run/uvm-g7-secrets/recovery-server.key",
        "UVM_G7_RECOVERY_TLS_CA_FILE": "/run/uvm-g7-secrets/recovery-ca.crt",
        "UVM_API_HOST": "0.0.0.0", "UVM_API_PORT": "8000",
    }
    cmd = ["docker", "run", "-d", "--name", container,
        "--label", f"volt.g7-preview.instance={args.instance}",
        "--publish", f"127.0.0.1:{info['api_port']}:8000",
        "--publish", f"127.0.0.1:{info['oidc_port']}:9000",
        "--mount", f"type=bind,src={secret_dir},dst=/run/secrets,readonly"]
    for part, volume in info["volumes"].items():
        target = {"postgres": "/var/lib/postgresql/data", "media": "/app/media", "state": "/opt/uvm/state"}[part]
        cmd += ["--mount", f"type=volume,src={volume},dst={target}"]
    for key, value in env.items():
        cmd += ["--env", f"{key}={value}"]
    cmd.append(image)
    run(*cmd)
    info["image"] = image
    info["image_id"] = run("docker", "inspect", "--format", "{{.Image}}", container, capture=True)
    (root / "instance.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    (root / "instance.json").chmod(0o600)
    print(f"container={container}\nimage={image}\nurl=http://127.0.0.1:{info['api_port']}/")


def docker_for(args, action: str) -> None:
    _root, info = load(args.instance)
    container = info["container"]
    if action == "status":
        names = run("docker", "ps", "-a", "--filter", f"name={container}", "--format", "{{.Names}}", capture=True)
        if container not in names.splitlines():
            print(f"container=absent name={container}")
            return
        run("docker", "ps", "-a", "--filter", f"name={container}", "--format", "{{.Names}} {{.Status}} {{.Image}}")
        return
    run("docker", action, container)


def wait_healthy(args) -> None:
    _root, info = load(args.instance)
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
    link = (root / "operator-link.json").read_text(encoding="utf-8").strip()
    # The operator credential is read inside the container and is never included in argv/output.
    program = "import json,urllib.request; p='/run/uvm-g7-secrets/oidc_operator_secret'; token=open(p).read().strip(); body=" + repr(link) + "; r=urllib.request.Request('http://127.0.0.1:8000/api/v1/auth/operator/links',data=body.encode(),headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'}); print(urllib.request.urlopen(r,timeout=10).read().decode())"
    run("docker", "exec", "-i", info["container"], "/opt/uvm/venv/bin/python", "-c", program)


def destroy(args) -> None:
    _root, info = load(args.instance)
    container = info["container"]
    existing = run("docker", "ps", "-a", "--filter", f"name={container}", "--format", "{{.Names}}", capture=True)
    if container in existing.splitlines():
        labels = run("docker", "inspect", "--format", "{{ index .Config.Labels \"volt.g7-preview.instance\" }}", container, capture=True)
        if labels != args.instance:
            raise SystemExit("refusing to remove a container without the exact preview ownership label")
        run("docker", "rm", "-f", container)
    for volume in info["volumes"].values():
        listed = run("docker", "volume", "ls", "--filter", f"name={volume}", "--format", "{{.Name}}", capture=True)
        if volume in listed.splitlines():
            labels = run("docker", "volume", "inspect", "--format", "{{ index .Labels \"volt.g7-preview.instance\" }}", volume, capture=True)
            if labels != args.instance:
                raise SystemExit(f"refusing to remove volume without exact preview ownership label: {volume}")
            run("docker", "volume", "rm", volume)
    shutil.rmtree(state_dir(args.instance))
    print(f"destroyed_owned_instance={args.instance}")


def smoke(args) -> None:
    _root, info = load(args.instance)
    evidence = Path(args.evidence)
    evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    command = ["node", "tools/g7_local_preview_smoke.mjs", "--origin",
        f"http://127.0.0.1:{info['api_port']}", "--evidence", str(evidence)]
    if args.readback:
        command.append("--readback")
    subprocess.run(command, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init"); p.add_argument("instance"); p.add_argument("--api-port", type=int, default=8180); p.add_argument("--oidc-port", type=int, default=8190); p.set_defaults(fn=initialize)
    p = sub.add_parser("start"); p.add_argument("instance"); p.add_argument("--image"); p.set_defaults(fn=start)
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
