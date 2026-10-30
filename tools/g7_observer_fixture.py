#!/usr/bin/env python3
"""Private disposable fixture setup for the observer-only G7 journey."""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import ssl
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
            "oidc_client_secret", "oidc_sync_secret", "oidc_operator_secret",
            "g7_preservation_source_token")
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
        for role_password in ("anchor-signer-password", "exporter-ro-password", "siem-exporter-password"):
            (host_dir / role_password).write_text(secrets.token_hex(32), encoding="ascii")
            (host_dir / role_password).chmod(0o600)
        private = host_dir / "ed25519.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        private.chmod(0o600)
        public = secrets_dir / "host-pub.pem"
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        public.chmod(0o644)
        ca_key, ca_cert = host_dir / "recovery-ca.key", secrets_dir / "recovery-ca.crt"
        server_key, server_csr = secrets_dir / "recovery-server.key", host_dir / "recovery-server.csr"
        server_cert = secrets_dir / "recovery-server.crt"
        client_key, client_csr = host_dir / "recovery-client.key", host_dir / "recovery-client.csr"
        client_cert = host_dir / "recovery-client.crt"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca_cert), "-subj", "/CN=G7 fixture recovery CA",
            "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for key, csr, cn in ((server_key, server_csr, "localhost"),
                (client_key, client_csr, "g7-local-controller")):
            subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={cn}"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (host_dir / "server.ext").write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
        (host_dir / "client.ext").write_text("extendedKeyUsage=clientAuth\n")
        for csr, cert, ext in ((server_csr, server_cert, host_dir / "server.ext"),
                (client_csr, client_cert, host_dir / "client.ext")):
            subprocess.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
                "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cert), "-days", "2",
                "-extfile", str(ext)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for path in (ca_key, server_key, client_key):
            path.chmod(0o600)
        for path in (ca_cert, server_cert, client_cert):
            path.chmod(0o644)
        (secrets_dir / "registry.json").write_text(json.dumps([{
            "deployment_id": "g7-local", "label": "Disposable G7 local",
            "host_principal_id": "g7-host", "verification_key_file": "/run/uvm-g7-host-pub.pem"}, {
            "deployment_id": "g7-other", "label": "Disposable G7 B (registered, ungranted)",
            "host_principal_id": "g7-host-b", "verification_key_file": "/run/uvm-g7-host-pub.pem"}],
            separators=(",", ":")), encoding="utf-8")
        (secrets_dir / "registry.json").chmod(0o644)
        oidc = f"http://{args.oidc_host}:{args.oidc_port}"
        api = f"http://127.0.0.1:{args.api_port}"
        internal_oidc = "http://127.0.0.1:9000"
        config = {"schema_version": 1, "provider_id": "g7-synthetic", "issuer": oidc,
            "discovery_url": (internal_oidc if args.oidc_internal else oidc) + "/.well-known/openid-configuration",
            "client_id": "g7-local-client", "callback_url": api + "/api/v1/auth/callback",
            "client_secret_file": "/run/uvm-g7-secrets/oidc_client_secret",
            "sync_secret_file": "/run/uvm-g7-secrets/oidc_sync_secret",
            "operator_secret_file": "/run/uvm-g7-secrets/oidc_operator_secret",
            "operator_actor_id": "g7-fixture-operator", "allowed_algorithms": ["RS256"],
            "allowed_endpoint_origins": sorted({api, oidc, *( [internal_oidc] if args.oidc_internal else [] )}),
            "source_scope_ceilings": [],
            "group_mappings": {}, "mapping_revision": 1,
            "session_ttl_seconds": 3600, "heartbeat_max_age_seconds": 120}
        identities = [{"subject": "g7-actor-subject", "groups": []}]
        if args.identity_access_ownership:
            identities.extend([
                {"subject": "g7-identity-user-subject", "groups": []},
                {"subject": "g7-identity-deny-subject", "groups": []},
            ])
        g7_scope = ("local", "g7-local", "all")
        service_principals = {
            "g7-host": {"token": values["uvm_cursor_secret"], "scopes": [],
                "actor_kind": "service", "origin": "g7-host-controller"},
            "g7-preservation-source": {"token": values["g7_preservation_source_token"],
                "scopes": [{"source_family": g7_scope[0], "source_account_id": g7_scope[1],
                    "scope_key": g7_scope[2]}], "actor_kind": "service",
                "origin": "g7-preservation-source-adapter",
                "service_grants": [
                    {"grant_id": "g7-source-preservation-read-v1", "action": "preservation.read",
                        "source_scopes": [{"source_family": g7_scope[0], "source_account_id": g7_scope[1], "scope_key": g7_scope[2]}],
                        "deployment_scopes": []},
                    {"grant_id": "g7-source-evidence-read-v1", "action": "preservation.evidence.read",
                        "source_scopes": [{"source_family": g7_scope[0], "source_account_id": g7_scope[1], "scope_key": g7_scope[2]}],
                        "deployment_scopes": []},
                    {"grant_id": "g7-source-deployment-audit-read-v1", "action": "audit.read.deployment",
                        "source_scopes": [{"source_family": g7_scope[0], "source_account_id": g7_scope[1], "scope_key": g7_scope[2]}],
                        "deployment_scopes": ["g7-local"]},
                    {"grant_id": "g7-source-deployment-audit-export-v1", "action": "audit.export.deployment",
                        "source_scopes": [{"source_family": g7_scope[0], "source_account_id": g7_scope[1], "scope_key": g7_scope[2]}],
                        "deployment_scopes": ["g7-local"]}]}}
        env = {
            "UVM_AUTH_MODE": "oidc", "UVM_OIDC_CONFIG": json.dumps(config, separators=(",", ":")),
            "UVM_OIDC_FIXTURE_SUBJECT": "g7-actor-subject",
            "UVM_OIDC_FIXTURE_IDENTITIES": json.dumps(identities, separators=(",", ":")),
            "UVM_OIDC_PROVIDER_PORT": "9000", "UVM_G7_DISPOSABLE_MODE": "1",
            "UVM_OIDC_BROWSER_AUTHORIZATION_ORIGIN": oidc if args.oidc_internal else "",
            "UVM_OIDC_INTERNAL_ENDPOINT_ORIGIN": internal_oidc if args.oidc_internal else "",
            "UVM_G3_BOOTSTRAP_PRINCIPAL": "g7-actor",
            "UVM_NATIVE_BOOTSTRAP_PRINCIPALS": "g7-actor",
            "UVM_API_PRINCIPALS": json.dumps(service_principals, separators=(",", ":")),
            "UVM_G7_SOURCE_ADAPTER_PRINCIPAL": "g7-preservation-source",
            "UVM_NATIVE_GRANTABLE_ENVELOPE": json.dumps({
                "actions": ["observer.timing.read", "observer.timing.configure",
                    "backup.settings.read", "backup.settings.configure", "assessment.read", "audit.read",
                    *( ["access_group.read", "ownership.team.read", "ownership.team.manage",
                        "owners.directory.read", "owners.assign", "portion.define"]
                        if args.identity_access_ownership else [] ),
                    "preservation.read", "preservation.evidence.read", "audit.read.deployment",
                    "audit.export.deployment", *( ["acceptance.submit", "acceptance.approve",
                    "warning.route.manage", "warning.actor_link.manage"] if args.exception_warning else [] )],
                "target_scope": {"group_ids": ["*"], "source_families": ["*"],
                    "environments": ["*"], "service_ids": ["*"], "membership_mode": "all_current"},
                "limits": {"maximum_acceptance_days": 2 if args.exception_warning else None, "maximum_severity": None,
                    "whole_group_confirmation": True, "allowed_environments": ["*"],
                    "allowed_service_ids": ["*"],
                    "allowed_sla_clock_bases": ["elapsed_utc_seconds", "calendar_days_utc"],
                    "allowed_sla_severities": ["critical", "high", "medium", "low", "informational"],
                    "allowed_sla_start_sources": ["source_observation_v1", "uvm_ingest_commit_v1"],
                    "maximum_sla_duration_seconds": None, "allow_sla_backfill": True,
                    "maximum_deadline_extension_seconds": None,
                    "allowed_identity_scalar_fields": {}},
                "separation_of_duties": {"approval_requires_distinct_actor": True,
                    "prohibit_requester_approval": not args.exception_warning, "required_approver_count": 1,
                    "prohibited_action_pairs": []},
                **({"warning_route_scope": {
                "installation_ids": ["fixture-installation"], "workspace_ids": ["T_FIXTURE"],
                "channel_ids": ["C_FIXTURE_SUCCESS", "C_FIXTURE_FAILED", "C_FIXTURE_UNCERTAIN",
                    "SMTP_FIXTURE_ACCEPTED", "SMTP_FIXTURE_RETRY", "SMTP_FIXTURE_UNCERTAIN",
                    "SMTP_FIXTURE_PREDATA"],
                "destination_refs": ["fixture-destination", "fixture-failed-destination",
                    "fixture-uncertain-destination", "fixture-smtp-accepted",
                    "fixture-smtp-retry", "fixture-smtp-uncertain",
                    "fixture-smtp-predatadisconnect"],
                "recipient_ids": ["g7-actor"], "channels": ["slack", "email"],
                "access_group_ids": ["00000000-0000-4000-8000-000000000024"],
                "failure_alert_group_ids": ["00000000-0000-4000-8000-000000000024"],
                "finding_group_ids": [str(uuid.uuid5(uuid.NAMESPACE_URL, 'volt:g7:recovery-fixture:group'))]}}
                    if args.exception_warning else {}),
                "source_scopes": [{"source_family": "local", "source_account_id": "g7-local",
                    "scope_key": "all"}], "deployment_scopes": ["g7-local", "g7-other"]},
                separators=(",", ":")),
            "UVM_OBSERVER_DEPLOYMENT_REGISTRY_FILE": "/run/uvm-g7-registry.json",
            "UVM_G7_INITIAL_MAXIMUM_FUTURE_SKEW_SECONDS": "30",
            "UVM_G7_HOST_KEY_ID": "g7-host-controller-key",
            "UVM_G7_CONTROLLER_INSTANCE_ID": "00000000-0000-4000-8000-000000000017",
            "UVM_G7_RECOVERY_TLS_CERT_FILE": "/run/uvm-g7-secrets/recovery-server.crt",
            "UVM_G7_RECOVERY_TLS_KEY_FILE": "/run/uvm-g7-secrets/recovery-server.key",
            "UVM_G7_RECOVERY_TLS_CA_FILE": "/run/uvm-g7-secrets/recovery-ca.crt",
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
        (secrets_dir / "source-operator-link.json").write_text(json.dumps({
            "issuer": oidc, "subject": "g7-preservation-source-subject",
            "principal_id": "g7-preservation-source",
            "display_label": "Synthetic G7 Preservation Source Adapter",
            "rationale": "Provision the separately credentialled local source inventory adapter",
            "evidence_ref": "g7-preservation-source-adapter-fixture"},
            separators=(",", ":")), encoding="utf-8")
        (secrets_dir / "source-operator-link.json").chmod(0o600)
        if args.identity_access_ownership:
            (secrets_dir / "identity-user-operator-link.json").write_text(json.dumps({
                "issuer": oidc, "subject": "g7-identity-user-subject",
                "principal_id": "g7-identity-user",
                "display_label": "Synthetic G7 Identity User",
                "rationale": "Link the separate identity acceptance principal",
                "evidence_ref": "g7-identity-access-ownership-fixture"},
                separators=(",", ":")), encoding="utf-8")
            (secrets_dir / "identity-user-operator-link.json").chmod(0o600)
            (secrets_dir / "identity-deny-operator-link.json").write_text(json.dumps({
                "issuer": oidc, "subject": "g7-identity-deny-subject",
                "principal_id": "g7-identity-deny-user",
                "display_label": "Synthetic G7 Explicit-Deny User",
                "rationale": "Link the separate explicit-deny acceptance principal",
                "evidence_ref": "g7-identity-access-ownership-explicit-deny"},
                separators=(",", ":")), encoding="utf-8")
            (secrets_dir / "identity-deny-operator-link.json").chmod(0o600)
        return

    if args.command == "link-identity-user":
        container = args.container or "volt-g7-identity-app"
        subprocess.run(["docker", "exec", container, "bash", "-lc",
            "curl --fail --silent --show-error -H 'Authorization: Bearer '$(cat /run/uvm-g7-secrets/oidc_operator_secret) "
            "-H 'Content-Type: application/json' --data-binary @/run/secrets/identity-user-operator-link.json "
            "http://127.0.0.1:8000/api/v1/auth/operator/links"], check=True)
        print("oidc_fixture_link=created")
        return

    if args.command == "link-identity-deny-user":
        container = args.container or "volt-g7-identity-app"
        subprocess.run(["docker", "exec", container, "bash", "-lc",
            "curl --fail --silent --show-error -H 'Authorization: Bearer '$(cat /run/uvm-g7-secrets/oidc_operator_secret) "
            "-H 'Content-Type: application/json' --data-binary @/run/secrets/identity-deny-operator-link.json "
            "http://127.0.0.1:8000/api/v1/auth/operator/links"], check=True)
        print("oidc_fixture_link=created")
        return

    if args.command == "anchor-init":
        ro_password = (host_dir / "anchor-ro-password").read_text(encoding="ascii").strip()
        signer_password = (host_dir / "anchor-signer-password").read_text(encoding="ascii").strip()
        exporter_password = (host_dir / "exporter-ro-password").read_text(encoding="ascii").strip()
        sink_password = (host_dir / "siem-exporter-password").read_text(encoding="ascii").strip()
        if not all(value.isalnum() for value in (ro_password, signer_password, exporter_password, sink_password)):
            raise RuntimeError("invalid generated anchor credential")
        anchor_container = args.container or "volt-g7-observer-anchor"
        subprocess.run(["docker", "exec", anchor_container, "bash", "-lc",
            "for i in $(seq 1 60); do /usr/lib/postgresql/18/bin/pg_isready -h 127.0.0.1 -p 5432 >/dev/null && exit 0; sleep 1; done; exit 1"], check=True)
        sql = "CREATE ROLE host_ro LOGIN PASSWORD '" + ro_password + "';"
        subprocess.run(["docker", "exec", anchor_container,
            "/usr/lib/postgresql/18/bin/psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", sql],
            check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["docker", "exec", anchor_container,
            "/usr/lib/postgresql/18/bin/createdb", "-U", "postgres", "-O", "postgres", "audit_anchor"],
            check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["docker", "exec", anchor_container,
            "/usr/lib/postgresql/18/bin/createdb", "-U", "postgres", "-O", "postgres", "audit_sink"],
            check=True, stdout=subprocess.DEVNULL)
        table_sql = ("CREATE ROLE anchor_signer LOGIN PASSWORD '" + signer_password + "';"
            "CREATE ROLE exporter_ro LOGIN PASSWORD '" + exporter_password + "';"
            "CREATE ROLE siem_exporter LOGIN PASSWORD '" + sink_password + "';"
            "CREATE SCHEMA uvm_audit_anchor;"
            "CREATE TABLE uvm_audit_anchor.inventory (deployment_id text NOT NULL, sink_id text NOT NULL,"
            "event_id uuid NOT NULL, event_sequence bigint NOT NULL, payload_sha256 text NOT NULL,"
            "sink_receipt text NOT NULL, affected_scope text NOT NULL, anchored_at timestamptz NOT NULL,"
            "contract_version text NOT NULL, PRIMARY KEY(deployment_id,sink_id,event_id));"
            "CREATE TABLE uvm_audit_anchor.incidents (incident_id uuid PRIMARY KEY, deployment_id text NOT NULL,"
            "sink_id text NOT NULL, event_id uuid NOT NULL, condition text NOT NULL, detected_at timestamptz NOT NULL,"
            "observed_at timestamptz NOT NULL, state text NOT NULL, evidence jsonb NOT NULL, contract_version text NOT NULL);"
            "GRANT USAGE ON SCHEMA uvm_audit_anchor TO host_ro,anchor_signer,exporter_ro;"
            "GRANT SELECT ON uvm_audit_anchor.inventory TO host_ro,exporter_ro;"
            "GRANT SELECT,INSERT ON uvm_audit_anchor.inventory TO anchor_signer;"
            "GRANT SELECT,INSERT ON uvm_audit_anchor.incidents TO anchor_signer,exporter_ro;"
            "GRANT SELECT ON uvm_audit_anchor.incidents TO host_ro;")
        subprocess.run(["docker", "exec", anchor_container,
            "/usr/lib/postgresql/18/bin/psql", "-U", "postgres", "-d", "audit_anchor", "-v", "ON_ERROR_STOP=1", "-c", table_sql],
            check=True, stdout=subprocess.DEVNULL)
        sink_sql = ("CREATE SCHEMA uvm_audit_export;"
            "CREATE TABLE uvm_audit_export.events (event_id uuid PRIMARY KEY, payload jsonb NOT NULL, committed_at timestamptz NOT NULL);"
            "GRANT USAGE ON SCHEMA uvm_audit_export TO siem_exporter;"
            "GRANT SELECT,INSERT ON uvm_audit_export.events TO siem_exporter;")
        subprocess.run(["docker", "exec", anchor_container,
            "/usr/lib/postgresql/18/bin/psql", "-U", "postgres", "-d", "audit_sink", "-v", "ON_ERROR_STOP=1", "-c", sink_sql],
            check=True, stdout=subprocess.DEVNULL)
        print("anchor_schema=ready; sink_schema=ready; host_ro=SELECT-only; exporter_ro=anchor-read/incident-insert; anchor_signer=insert-only-inventory; siem_exporter=sink-read-insert")
        return

    if args.command == "link-actor":
        container = args.container or "volt-g7-observer-journey"
        subprocess.run(["docker", "exec", container, "bash", "-lc",
            "curl --fail --silent --show-error -H 'Authorization: Bearer '$(cat /run/uvm-g7-secrets/oidc_operator_secret) "
            "-H 'Content-Type: application/json' --data-binary @/run/secrets/operator-link.json "
            "http://127.0.0.1:8000/api/v1/auth/operator/links"], check=True)
        subprocess.run(["docker", "exec", container, "bash", "-lc",
            "curl --fail --silent --show-error -H 'Authorization: Bearer '$(cat /run/uvm-g7-secrets/oidc_operator_secret) "
            "-H 'Content-Type: application/json' --data-binary @/run/secrets/source-operator-link.json "
            "http://127.0.0.1:8000/api/v1/auth/operator/links"], check=True)
        print("oidc_fixture_link=created")
        return

    if args.command == "backup-policy":
        now = datetime.now(timezone.utc).replace(microsecond=0)
        policy = {"revision": 1,
            "bounds": {
                "interval_seconds": {"min": 60, "max": 3600},
                "timeout_seconds": {"min": 1, "max": 1800},
                "maximum_backup_age_seconds": {"min": 60, "max": 86400},
                "restore_verification_timeout_seconds": {"min": 1, "max": 3600}},
            "archive_target_refs": ["archive-target-local-a"],
            "recovery_profile_refs": ["recovery-profile-local-a"],
            "maximum_report_age_seconds": 300, "maximum_future_skew_seconds": 30}
        policy["digest"] = "sha256:" + hashlib.sha256(json.dumps(policy,
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode("utf-8")).hexdigest()
        observed = now.isoformat().replace("+00:00", "Z")
        fresh_until = (now + timedelta(seconds=300)).isoformat().replace("+00:00", "Z")
        unsigned = {"schema_version": 1, "deployment_id": "g7-local",
            "report_id": str(uuid.uuid4()), "sequence": 1,
            "controller_instance_id": "00000000-0000-4000-8000-000000000017",
            "report_kind": "policy", "host_policy": policy,
            "desired": None, "settings_application": None, "completed_archive": None,
            "freshness": None, "restore_verification": None, "recovery_epoch": None,
            "observed_at": observed, "fresh_until": fresh_until}
        signed = host.signed_report({"signing_key_file": str(host_dir / "ed25519.pem")}, unsigned)
        signed["signature"] = {"algorithm": "Ed25519",
            "key_id": "g7-host-controller-key", "value": signed["signature"]}
        token = (secrets_dir / "uvm_cursor_secret").read_text(encoding="utf-8").strip()
        request = urllib.request.Request(f"https://127.0.0.1:{args.recovery_port}/recovery-control/v1/g7-local/reports",
            data=json.dumps(signed, sort_keys=True, separators=(",", ":")).encode(),
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            method="POST")
        tls = ssl.create_default_context(cafile=str(secrets_dir / "recovery-ca.crt"))
        tls.load_cert_chain(str(host_dir / "recovery-client.crt"), str(host_dir / "recovery-client.key"))
        deadline = time.monotonic() + 60
        while True:
            try:
                with urllib.request.urlopen(request, timeout=10, context=tls) as response:
                    result = json.loads(response.read())
                break
            except urllib.error.HTTPError as exc:
                if exc.code < 500:
                    raise
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)
            except urllib.error.URLError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)
        print(json.dumps({"host_policy_revision": result["host_policy_revision"],
            "report_id": result["report_id"], "accepted": result["accepted"]}, separators=(",", ":")))
        host.atomic_json(host_dir / "backup-policy.json", policy)
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
            "endpoint": f"http://127.0.0.1:{args.api_port}", "token_file": str(token_file),
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

    if args.command == "backup-host-config":
        backup_dir = state / "backup"
        backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        accepted_policy = host.read_json(host_dir / "backup-policy.json")
        if not isinstance(accepted_policy, dict):
            raise SystemExit("accepted backup host policy is unavailable")
        config = {"schema_version": 1, "deployment_id": "g7-local",
            "endpoint": f"https://127.0.0.1:{args.recovery_port}", "token_file": str(host_dir / "api-token"),
            "client_cert_file": str(host_dir / "recovery-client.crt"),
            "client_key_file": str(host_dir / "recovery-client.key"),
            "server_ca_file": str(secrets_dir / "recovery-ca.crt"),
            "signing_key_file": str(host_dir / "ed25519.pem"),
            "signing_key_id": "g7-host-controller-key",
            "controller_instance_id": "00000000-0000-4000-8000-000000000017",
            "host_policy": accepted_policy,
            "journal_file": str(backup_dir / "controller-journal.json"),
            "active_settings_file": str(backup_dir / "active-settings.json"),
            "scheduler_readback_file": str(backup_dir / "scheduler-readback.json"),
            "capture_request_file": str(backup_dir / "capture-request.json")}
        config_path = host_dir / "backup-controller.json"
        host.atomic_json(config_path, config)
        import tools.g7_backup_controller as backup_controller
        backup_controller.atomic_json(Path(config["journal_file"]), {
            "schema_version": 1, "deployment_id": "g7-local",
            "controller_instance_id": config["controller_instance_id"],
            "last_sequence": 1, "recovery_epoch_floor": 0,
            "last_intent": None, "last_ack": None})
        scheduler_log = (host_dir / "backup-scheduler.log").open("ab")
        scheduler = subprocess.Popen([sys.executable, "tools/g7_backup_scheduler.py",
            "--config", str(config_path)], cwd=Path(__file__).resolve().parents[1],
            stdout=scheduler_log, stderr=scheduler_log, start_new_session=True)
        (host_dir / "backup-scheduler.pid").write_text(str(scheduler.pid))
        scheduler_log.close()
        print(json.dumps({"controller_config": str(config_path),
            "journal_sequence": 1, "host_policy_revision": accepted_policy["revision"]},
            separators=(",", ":")))
        return

    if args.command == "backup-host-once":
        completed = subprocess.run(["uv", "run", "python", "tools/g7_backup_controller.py",
            "--config", str(host_dir / "backup-controller.json"), "--once"],
            cwd=Path(__file__).resolve().parents[1], check=False,
            capture_output=True, text=True)
        if completed.returncode:
            # The controller output is bounded and contains exception class/message only;
            # retain it in the outer journey log so failures remain diagnosable.
            if completed.stdout.strip():
                print(completed.stdout.strip())
            if completed.stderr.strip():
                print(completed.stderr.strip(), file=sys.stderr)
            raise SystemExit(completed.returncode)
        print(completed.stdout.strip())
        return

    if args.command == "host-once":
        completed = subprocess.run([sys.executable, "tools/g7_host_observer.py",
            "controller", "--policy", str(host_dir / "policy.json"), "--once"],
            cwd=Path(__file__).resolve().parents[1], check=True,
            capture_output=True, text=True)
        print(completed.stdout.strip())
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
        elif args.action == "terminate":
            try:
                os.killpg(pid, signal.SIGTERM)
                os.killpg(pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
            time.sleep(0.5)
            pid_file.write_text("0", encoding="ascii")
        elif args.action == "start":
            output = (host_dir / f"{args.role}.log").open("ab", buffering=0)
            process = subprocess.Popen(["uv", "run", "python", "tools/g7_host_observer.py",
                args.role, "--policy", str(host_dir / "policy.json")],
                cwd=Path(__file__).resolve().parents[1], stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            pid_file.write_text(str(process.pid), encoding="ascii")
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
    parser.add_argument("command", choices=("create", "anchor-init", "link-actor", "link-identity-user", "link-identity-deny-user", "backup-policy", "host-config", "backup-host-config", "backup-host-once", "host-control", "host-once", "host-report-attacks", "host-telemetry-count"))
    parser.add_argument("--role", choices=("observer", "supervisor", "controller"))
    parser.add_argument("--action", choices=("stop", "resume", "restart", "start", "terminate", "tighten-policy", "restore-policy"))
    parser.add_argument("--report-id")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--image", default="")
    parser.add_argument("--anchor-port", type=int, default=5433)
    parser.add_argument("--container")
    parser.add_argument("--oidc-port", type=int, default=9000)
    parser.add_argument("--oidc-host", default="127.0.0.1")
    parser.add_argument("--oidc-internal", action="store_true")
    parser.add_argument("--api-port", type=int, default=8000)
    parser.add_argument("--recovery-port", type=int, default=8002)
    parser.add_argument("--exception-warning", action="store_true")
    parser.add_argument("--identity-access-ownership", action="store_true")
    args = parser.parse_args()
    run(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
