#!/usr/bin/env python3
"""Private disposable fixture setup for the observer-only G7 journey."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import time
from urllib.parse import quote
import uuid
import urllib.error
import urllib.request
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import g7_host_observer as host


def run(args: argparse.Namespace) -> None:
    root = args.root
    secrets_dir = root / "secrets"
    host_dir = root / "host"
    state = host_dir / "state"
    secrets_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    host_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    (root / "scheduler").mkdir(parents=True, exist_ok=True, mode=0o777)

    if args.command == "create":
        names = ("uvm_db_password", "ce_db_password", "ce_admin_password",
            "ce_secret_key", "ce_credential_key", "uvm_cursor_secret",
            "oidc_client_secret", "oidc_sync_secret", "oidc_operator_secret")
        values = {name: secrets.token_urlsafe(32) for name in names}
        for name, value in values.items():
            path = secrets_dir / name
            path.write_text(value + "\n", encoding="utf-8")
            path.chmod(0o600)
        (root / "anchor-password").write_text(secrets.token_hex(32) + "\n", encoding="ascii")
        # RUN_ROOT is mode 0700 on the host; the separately mounted sidecar
        # needs only read access under its unprivileged postgres UID.
        (root / "anchor-password").chmod(0o644)
        (host_dir / "anchor-ro-password").write_text(secrets.token_hex(32), encoding="ascii")
        (host_dir / "anchor-ro-password").chmod(0o600)
        private = host_dir / "ed25519.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        private.chmod(0o600)
        public = secrets_dir / "host-pub.pem"
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        public.chmod(0o644)
        (secrets_dir / "registry.json").write_text(json.dumps([{
            "deployment_id": "g7-local", "label": "Disposable G7 local",
            "host_principal_id": "g7-host", "verification_key_file": "/run/uvm-g7-host-pub.pem"}],
            separators=(",", ":")), encoding="utf-8")
        (secrets_dir / "registry.json").chmod(0o644)
        oidc = "http://127.0.0.1:9000"
        api = "http://127.0.0.1:8000"
        config = {"schema_version": 1, "provider_id": "g7-synthetic", "issuer": oidc,
            "discovery_url": oidc + "/.well-known/openid-configuration",
            "client_id": "g7-local-client", "callback_url": api + "/api/v1/auth/callback",
            "client_secret_file": "/run/uvm-g7-secrets/oidc_client_secret",
            "sync_secret_file": "/run/uvm-g7-secrets/oidc_sync_secret",
            "operator_secret_file": "/run/uvm-g7-secrets/oidc_operator_secret",
            "operator_actor_id": "g7-fixture-operator", "allowed_algorithms": ["RS256"],
            "allowed_endpoint_origins": [api, oidc], "source_scope_ceilings": [],
            "group_mappings": {}, "mapping_revision": 1,
            "session_ttl_seconds": 3600, "heartbeat_max_age_seconds": 120}
        identities = [{"subject": "g7-actor-subject", "groups": []}]
        env = {
            "UVM_AUTH_MODE": "oidc", "UVM_OIDC_CONFIG": json.dumps(config, separators=(",", ":")),
            "UVM_OIDC_FIXTURE_SUBJECT": "g7-actor-subject",
            "UVM_OIDC_FIXTURE_IDENTITIES": json.dumps(identities, separators=(",", ":")),
            "UVM_OIDC_PROVIDER_PORT": "9000", "UVM_G7_DISPOSABLE_MODE": "1",
            "UVM_G3_BOOTSTRAP_PRINCIPAL": "g7-actor",
            "UVM_NATIVE_BOOTSTRAP_PRINCIPALS": "g7-actor",
            "UVM_API_PRINCIPALS": json.dumps({"g7-host": {"token": values["uvm_cursor_secret"],
                "scopes": [], "actor_kind": "service", "origin": "g7-host-controller"}},
                separators=(",", ":")),
            "UVM_NATIVE_GRANTABLE_ENVELOPE": json.dumps({
                "actions": ["observer.timing.read", "observer.timing.configure", "audit.read"],
                "target_scope": {"group_ids": ["*"], "source_families": ["*"],
                    "environments": ["*"], "service_ids": ["*"], "membership_mode": "all_current"},
                "limits": {"maximum_acceptance_days": None, "maximum_severity": None,
                    "whole_group_confirmation": True, "allowed_environments": ["*"],
                    "allowed_service_ids": ["*"],
                    "allowed_sla_clock_bases": ["elapsed_utc_seconds", "calendar_days_utc"],
                    "allowed_sla_severities": ["critical", "high", "medium", "low", "informational"],
                    "allowed_sla_start_sources": ["source_observation_v1", "uvm_ingest_commit_v1"],
                    "maximum_sla_duration_seconds": None, "allow_sla_backfill": True,
                    "maximum_deadline_extension_seconds": None,
                    "allowed_identity_scalar_fields": {}},
                "separation_of_duties": {"approval_requires_distinct_actor": True,
                    "prohibit_requester_approval": True, "required_approver_count": 1,
                    "prohibited_action_pairs": []},
                "source_scopes": [{"source_family": "local", "source_account_id": "g7-local",
                    "scope_key": "all"}], "deployment_scopes": ["g7-local", "g7-other"]},
                separators=(",", ":")),
            "UVM_OBSERVER_DEPLOYMENT_REGISTRY_FILE": "/run/uvm-g7-registry.json",
            "DD_ADMIN_USER": "admin", "DD_ADMIN_MAIL": "admin@defectdojo.local",
            "DD_ADMIN_FIRST_NAME": "Synthetic", "DD_ADMIN_LAST_NAME": "Operator",
            "DD_INITIALIZE": "true", "DD_ALLOWED_HOSTS": "localhost,127.0.0.1",
            "UVM_API_HOST": "0.0.0.0", "UVM_API_PORT": "8000"}
        (root / "container.env").write_text("".join(f"{k}={v}\n" for k, v in env.items()), encoding="utf-8")
        (root / "container.env").chmod(0o600)
        (secrets_dir / "operator-link.json").write_text(json.dumps({
            "issuer": oidc, "subject": "g7-actor-subject", "principal_id": "g7-actor",
            "display_label": "Synthetic G7 Operator", "rationale": "Disposable observer settings journey fixture",
            "evidence_ref": "g7-observer-journey-fixture"}, separators=(",", ":")), encoding="utf-8")
        (secrets_dir / "operator-link.json").chmod(0o600)
        return

    if args.command == "anchor-init":
        ro_password = (host_dir / "anchor-ro-password").read_text(encoding="ascii").strip()
        subprocess.run(["docker", "exec", "volt-g7-observer-anchor", "bash", "-lc",
            "for i in $(seq 1 60); do /usr/lib/postgresql/18/bin/pg_isready -h 127.0.0.1 -p 5432 >/dev/null && exit 0; sleep 1; done; exit 1"], check=True)
        sql = "CREATE ROLE host_ro LOGIN PASSWORD '" + ro_password + "';"
        subprocess.run(["docker", "exec", "volt-g7-observer-anchor",
            "/usr/lib/postgresql/18/bin/psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", sql],
            check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["docker", "exec", "volt-g7-observer-anchor",
            "/usr/lib/postgresql/18/bin/createdb", "-U", "postgres", "-O", "postgres", "audit_anchor"],
            check=True, stdout=subprocess.DEVNULL)
        table_sql = ("CREATE SCHEMA uvm_audit_anchor;"
            "CREATE TABLE uvm_audit_anchor.inventory (event_id uuid NOT NULL, payload_sha256 text NOT NULL,"
            "sink_receipt text NOT NULL, anchored_at timestamptz NOT NULL, deployment_id text NOT NULL, sink_id text NOT NULL,"
            "PRIMARY KEY(deployment_id,sink_id,event_id));"
            "GRANT USAGE ON SCHEMA uvm_audit_anchor TO host_ro;"
            "GRANT SELECT ON uvm_audit_anchor.inventory TO host_ro;")
        subprocess.run(["docker", "exec", "volt-g7-observer-anchor",
            "/usr/lib/postgresql/18/bin/psql", "-U", "postgres", "-d", "audit_anchor", "-v", "ON_ERROR_STOP=1", "-c", table_sql],
            check=True, stdout=subprocess.DEVNULL)
        print("anchor_schema=ready; host_ro=SELECT-only")
        return

    if args.command == "link-actor":
        subprocess.run(["docker", "exec", "volt-g7-observer-journey", "bash", "-lc",
            "curl --fail --silent --show-error -H 'Authorization: Bearer '$(cat /run/uvm-g7-secrets/oidc_operator_secret) "
            "-H 'Content-Type: application/json' --data-binary @/run/secrets/operator-link.json "
            "http://127.0.0.1:8000/api/v1/auth/operator/links"], check=True)
        print("oidc_fixture_link=created")
        return

    if args.command == "host-config":
        host_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
        token = (secrets_dir / "uvm_cursor_secret").read_text(encoding="utf-8").strip()
        token_file = host_dir / "api-token"
        token_file.write_text(token + "\n", encoding="ascii"); token_file.chmod(0o600)
        password = quote((host_dir / "anchor-ro-password").read_text(encoding="ascii"), safe="")
        bounds = {field: {"min": 0 if field == "maximum_future_skew_seconds" else 1, "max": 3600}
            for field in host.FIELDS}
        policy = {"schema_version": 1, "deployment_id": "g7-local", "revision": 1,
            "bounds": bounds, "freshness_seconds": 60, "poll_seconds": 1,
            "controller_request_timeout_seconds": 8, "apply_deadline_seconds": 35,
            "endpoint": "http://127.0.0.1:8000", "token_file": str(token_file),
            "sink_id": "g7-local-fixture", "anchor_read_dsn":
                "postgresql://host_ro:" + password + "@127.0.0.1:" + str(args.anchor_port) + "/audit_anchor",
            "signing_key_file": str(host_dir / "ed25519.pem"),
            "state_dir": str(state), "active_file": str(state / "active.json"),
            "scheduler_file": str(root / "scheduler" / "progress.json"),
            "observer_readback": str(state / "observer-readback.json"),
            "supervisor_readback": str(state / "supervisor-readback.json"),
            "observer_state": str(state / "observer-state.json"),
            "supervisor_state": str(state / "supervisor-state.json")}
        policy["host_policy_digest"] = host.digest(policy)
        policy_path = host_dir / "policy.json"
        host.atomic_json(policy_path, policy)
        for mode in ("observer", "supervisor", "controller"):
            output = (host_dir / f"{mode}.log").open("ab", buffering=0)
            process = subprocess.Popen(["uv", "run", "python", "tools/g7_host_observer.py",
                mode, "--policy", str(policy_path)], cwd=Path(__file__).resolve().parents[1],
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                start_new_session=True)
            (host_dir / f"{mode}.pid").write_text(str(process.pid), encoding="ascii")
        print("host_processes=observer,supervisor,controller")
        return

    if args.command == "host-control":
        if args.role not in {"observer", "supervisor", "controller"}:
            raise SystemExit("invalid host role")
        pid_file = host_dir / f"{args.role}.pid"
        if not pid_file.is_file():
            raise SystemExit("host process PID is unavailable")
        pid = int(pid_file.read_text(encoding="ascii"))
        if args.action == "stop":
            os.killpg(pid, signal.SIGSTOP)
        elif args.action == "resume":
            os.killpg(pid, signal.SIGCONT)
        elif args.action == "restart":
            try:
                os.killpg(pid, signal.SIGTERM)
                os.killpg(pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
            time.sleep(0.5)
            output = (host_dir / f"{args.role}.log").open("ab", buffering=0)
            process = subprocess.Popen(["uv", "run", "python", "tools/g7_host_observer.py",
                args.role, "--policy", str(host_dir / "policy.json")],
                cwd=Path(__file__).resolve().parents[1], stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            pid_file.write_text(str(process.pid), encoding="ascii")
        elif args.action in {"tighten-policy", "restore-policy"}:
            policy_path = host_dir / "policy.json"
            policy = host.read_json(policy_path)
            policy["revision"] += 1
            policy["bounds"]["request_deadline_seconds"]["max"] = (
                5 if args.action == "tighten-policy" else 3600)
            unsigned = {key: value for key, value in policy.items() if key != "host_policy_digest"}
            policy["host_policy_digest"] = host.digest(unsigned)
            host.atomic_json(policy_path, policy)
            try:
                os.killpg(pid, signal.SIGTERM)
                os.killpg(pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
            time.sleep(0.5)
            output = (host_dir / "controller.log").open("ab", buffering=0)
            process = subprocess.Popen(["uv", "run", "python", "tools/g7_host_observer.py",
                "controller", "--policy", str(policy_path)],
                cwd=Path(__file__).resolve().parents[1], stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            pid_file.write_text(str(process.pid), encoding="ascii")
        print(f"host_process={args.role} action={args.action}")
        return

    if args.command == "host-report-attacks":
        policy = host.read_json(host_dir / "policy.json")
        journal = host.read_json(state / "journal.json", default={}) or {}
        pending = journal.get("pending_report")
        if not isinstance(pending, dict):
            last_good = journal.get("last_good") or {}
            requested = {key: last_good.get(key) for key in
                ("revision", "digest", "values", "command_id", "intent_id")}
            if requested.get("revision") is None:
                raise SystemExit("no admitted observer revision for report attack fixture")
            requested["expected_host_policy_revision"] = policy["revision"]
            pending = host._report(policy, journal, requested, "applied", None)
        url = host._root(policy) + "/host/reports"
        token = (host_dir / "api-token").read_text(encoding="ascii").strip()

        def post(report: dict) -> tuple[int, str | None, str | None]:
            request = urllib.request.Request(url,
                data=json.dumps(report, sort_keys=True, separators=(",", ":")).encode(),
                headers={"Authorization": "Bearer " + token,
                    "Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=8) as response:
                    return response.status, None, None
            except urllib.error.HTTPError as error:
                try:
                    body = json.loads(error.read())
                    detail = body.get("error", {})
                    return error.code, detail.get("code"), detail.get("message", "")[:120]
                except (ValueError, AttributeError):
                    return error.code, None, None

        forged = copy.deepcopy(pending)
        import base64
        forged["signature"] = base64.urlsafe_b64encode(b"\x00" * 64).decode("ascii").rstrip("=")
        forged_status, forged_code, forged_message = post(forged)

        stale_unsigned = {key: value for key, value in pending.items() if key != "signature"}
        stale_unsigned.update(report_id=str(uuid.uuid4()), sequence=1,
            observed_at=host.utc_now(),
            consumers={name: {**item, "observed_at": host.utc_now()}
                for name, item in stale_unsigned["consumers"].items()})
        stale_status, stale_code, _ = post(host.signed_report(policy, stale_unsigned))

        conflicting = {key: value for key, value in pending.items() if key != "signature"}
        conflicting.update(report_id=args.report_id,
            sequence=max(int(journal.get("sequence", 0)) + 1,
                int(pending.get("sequence", 0)) + 1),
            failure_code="fixture_conflicting_report")
        conflicting_status, conflicting_code, _ = post(host.signed_report(policy, conflicting))
        print(json.dumps({"forged": forged_status, "stale": stale_status,
            "stale_code": stale_code, "conflicting": conflicting_status,
            "conflicting_code": conflicting_code, "forged_code": forged_code,
            "forged_message": forged_message}, sort_keys=True))
        return

    if args.command == "host-telemetry-count":
        policy = host.read_json(host_dir / "policy.json")
        token = (host_dir / "api-token").read_text(encoding="ascii").strip()
        url = host._root(policy) + "/host/telemetry?limit=1000&sink_id=g7-local-fixture"
        request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(request, timeout=8) as response:
            body = json.loads(response.read())
        print(json.dumps({"audit_event_count": len(body.get("audit_events", [])),
            "audit_complete": body.get("audit_complete")}, sort_keys=True))
        return

    raise SystemExit("unknown fixture command")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("create", "anchor-init", "link-actor", "host-config", "host-control", "host-report-attacks", "host-telemetry-count"))
    parser.add_argument("--role", choices=("observer", "supervisor", "controller"))
    parser.add_argument("--action", choices=("stop", "resume", "restart", "tighten-policy", "restore-policy"))
    parser.add_argument("--report-id")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--image", default="")
    parser.add_argument("--anchor-port", type=int, default=5433)
    args = parser.parse_args()
    run(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
