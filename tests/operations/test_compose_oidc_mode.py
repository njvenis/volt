from __future__ import annotations

import json
import hashlib
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import subprocess

from uvm.auth.service import load_oidc_config
from deploy.compose.setup import (allowed_host_names, compose_environment, demo_identity,
                                  demo_password_verifier, inspect_image, validate_external,
                                  validate_okta_publisher, compose_files, identity_secret_sources,
                                  validate_identity_secret_mounts, resolved_compose, compose,
                                  local_auth_configuration, compose_env_line,
                                  compose_instance_path, exclusive_instance_lock,
                                  capability_from_delivery, load_instance, SECRET_SIZES)


def config() -> dict:
    return {
        "schema_version": 1, "provider_id": "test-provider", "issuer": "https://id.example.org/",
        "discovery_url": "https://id.example.org/.well-known/openid-configuration",
        "client_id": "volt-test", "callback_url": "https://volt.example.org/api/v1/auth/callback",
        "client_secret_file": "/run/uvm-g7-secrets/oidc_client_secret",
        "sync_secret_file": "/run/uvm-g7-secrets/oidc_sync_secret",
        "operator_secret_file": "/run/uvm-g7-secrets/oidc_operator_secret",
        "operator_actor_id": "test-operator", "allowed_algorithms": ["RS256"],
        "allowed_endpoint_origins": ["https://id.example.org", "https://volt.example.org"],
        "source_scope_ceilings": [], "group_mappings": {}, "mapping_revision": 1,
        "session_ttl_seconds": 3600, "heartbeat_max_age_seconds": 120,
    }


class ExternalOIDCModeTests(unittest.TestCase):
    def test_identity_secret_mounts_are_mode_specific_for_all_install_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); secrets = root / "secrets"; secrets.mkdir()
            demo_credential = secrets / "demo_admin_credentials"
            demo_credential.write_text('{"schema":"uvm.demo-credential.v1"}\n'); demo_credential.chmod(0o600)
            publisher_config = root / "okta-publisher.json"; publisher_config.write_text('{"schema_version":1}\n'); publisher_config.chmod(0o600)
            private_key = secrets / "okta_service_private_key"; private_key.write_text("synthetic-key-bytes\n"); private_key.chmod(0o600)
            cases = (
                ({"mode":"demo", "okta_publisher_config_sha256":None},
                    {"demo-admin-credentials":demo_credential}),
                ({"mode":"external", "okta_publisher_config_sha256":None}, {}),
                ({"mode":"external", "okta_publisher_config_sha256":"sha256-test"},
                    {"okta-publisher.json":publisher_config,"okta_service_private_key":private_key}),
                ({"mode":"local", "okta_publisher_config_sha256":None}, {}),
            )
            for info, expected in cases:
                with self.subTest(mode=info["mode"], publisher=bool(expected)):
                    actual = identity_secret_sources(root, info)
                    self.assertEqual(actual, expected)
                    refs = [{"source":name,"target":f"/run/secrets/{name}"} for name in expected]
                    definitions = {name:{"file":str(path)} for name,path in expected.items()}
                    resolved = {"secrets":definitions}
                    validate_identity_secret_mounts(resolved,{"secrets":refs},expected,info)

    def test_identity_compose_overlay_selection_and_missing_secret_fail_before_compose(self):
        info = {"mode":"demo", "compose_directory":"/package/compose",
            "okta_publisher_config_sha256":None}
        self.assertEqual(compose_files(info),["-f","/package/compose/compose.yaml","-f","/package/compose/demo.yaml"])
        external = {"mode":"external", "compose_directory":"/package/compose",
            "okta_publisher_config_sha256":"sha256-test"}
        self.assertIn("/package/compose/okta-publisher.yaml",compose_files(external))
        external["okta_publisher_config_sha256"] = None
        self.assertNotIn("/package/compose/okta-publisher.yaml",compose_files(external))
        local = {"mode":"local", "compose_directory":"/package/compose"}
        self.assertEqual(compose_files(local),["-f","/package/compose/compose.yaml","-f","/package/compose/local.yaml"])
        restoring = {**local, "restore_pending":True, "restore_imported":True}
        self.assertEqual(compose_files(restoring)[-2:], ["-f","/package/compose/local-restore.yaml"])
        restoring["restore_capabilities_revoked"] = True
        self.assertEqual(compose_files(restoring)[-2:], ["-f","/package/compose/local-restore.yaml"])
        restoring["restore_sessions_revoked"] = True
        self.assertEqual(compose_files(restoring), compose_files(local))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/".env").write_text("test\n")
            info={**info,"env_sha256":hashlib.sha256((root/".env").read_bytes()).hexdigest()}
            with patch("deploy.compose.setup.command") as compose_command:
                with self.assertRaisesRegex(SystemExit,"demo-admin-credentials"):
                    resolved_compose(root,info)
                compose_command.assert_not_called()

    def test_wrong_mode_identity_secret_mounts_are_rejected(self):
        for mode, forbidden in (("demo","okta_service_private_key"),("external","demo-admin-credentials")):
            with self.subTest(mode=mode), self.assertRaisesRegex(SystemExit,"exact admitted deployment mode"):
                validate_identity_secret_mounts({"secrets":{forbidden:{"file":"/private/source"}}},
                    {"secrets":[{"source":forbidden,"target":f"/run/secrets/{forbidden}"}]},{},
                    {"mode":mode})

    def test_external_without_publisher_rejects_both_unadmitted_okta_secrets_before_start(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);env_file=root/".env";env_file.write_text("isolated\n")
            (root/"oidc.json").write_text("{}\n")
            project="volt-external-no-publisher"
            info={"mode":"external","project":project,"compose_directory":"/synthetic/compose",
                "image":"ghcr.io/example/volt:test","platform":"linux/amd64","owner_token":"synthetic-owner",
                "env_sha256":hashlib.sha256(env_file.read_bytes()).hexdigest(),
                "okta_publisher_config_sha256":None}
            secrets={name:{"file":str(root/name)} for name in ("okta-publisher.json","okta_service_private_key")}
            service={"image":info["image"],"platform":info["platform"],
                "labels":{"volt.compose.owner-token":info["owner_token"]},
                "volumes":[{"type":"volume","source":"postgres","target":"/var/lib/postgresql/data"},
                    {"type":"volume","source":"media","target":"/app/media"},
                    {"type":"volume","source":"state","target":"/opt/uvm/state"},
                    {"type":"bind","source":str(root/"oidc.json"),"target":"/etc/volt/oidc.json"}],
                "secrets":[{"source":name,"target":f"/run/secrets/{name}"} for name in secrets]}
            resolved={"services":{"volt":service},"secrets":secrets,
                "volumes":{part:{"name":f"{project}_{part}"} for part in ("postgres","media","state")},
                "networks":{"application":{"name":f"{project}_network"}}}
            with patch("deploy.compose.setup.load_instance",return_value=(root,info)), \
                 patch("deploy.compose.setup.command",return_value=json.dumps(resolved)) as docker:
                with self.assertRaisesRegex(SystemExit,"exact admitted deployment mode"):
                    compose(SimpleNamespace(directory=str(root)),"up")
            docker.assert_called_once()
            argv=docker.call_args.args
            self.assertIn("config",argv)
            self.assertNotIn("up",argv)

    def test_demo_administrator_uses_named_stable_synthetic_identity(self):
        self.assertEqual(demo_identity("nicho-testing-admin", "local-subject-7"),
                         ("nicho-testing-admin", "local-subject-7"))
        self.assertEqual(demo_identity(None, None),
                         ("volt-compose-demo-admin", "volt-compose-demo-admin-subject"))

    def test_demo_administrator_rejects_display_text_as_identity(self):
        for principal, subject in (("testing admin", "subject"), ("principal", ""),
                                   ("principal", "subject\n")):
            with self.subTest(principal=principal, subject=subject), self.assertRaisesRegex(
                    SystemExit, "stable .*(principal ID|provider subject)"):
                demo_identity(principal, subject)

    def test_demo_password_setup_stores_only_salted_scrypt_verifier(self):
        password = "long-demo-admin-password"
        value = json.loads(demo_password_verifier("local-admin", password, password))
        self.assertEqual(value["schema"], "uvm.demo-credential.v1")
        self.assertEqual(set(value), {"schema", "username", "salt", "password_hash"})
        self.assertNotIn(password, json.dumps(value))
        self.assertEqual(hashlib.scrypt(password.encode(), salt=bytes.fromhex(value["salt"]),
            n=2**15, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024).hex(), value["password_hash"])

    def test_local_auth_file_binds_exact_install_key_delivery_session_and_peer_scope(self):
        import uuid
        installation = str(uuid.uuid4())
        key_id = str(uuid.uuid4())
        config = local_auth_configuration(installation, key_id,
            "http://127.0.0.1:46180", 46180, "10.240.0.1")
        self.assertEqual(config["schema_version"], 1)
        self.assertEqual(config["installation_id"], installation)
        self.assertEqual(config["secret_source"], {"kind":"encrypted_local_v1",
            "secret_source_id":key_id,"key_path":"/run/uvm-connector/local-key"})
        self.assertEqual(config["bootstrap_delivery"], {"kind":"private_file",
            "path":"/run/volt-bootstrap/capability"})
        self.assertEqual(config["session_policy"], {"ttl_seconds":3600})
        self.assertEqual(config["trusted_ingress"]["allowed_peer_cidrs"],
            ["127.0.0.1/32", "10.240.0.1/32"])
        with self.assertRaisesRegex(SystemExit, "exact loopback HTTP origin"):
            local_auth_configuration(installation, key_id, "https://volt.example.org", 46180,
                                     "10.240.0.1")

    def test_runtime_helper_persists_the_host_bind_path_without_rewriting_spaces_or_dollars(self):
        host_path = "/home/Operator/VOLT work/$archive/instance"
        self.assertEqual(compose_instance_path(Path("/state"), runtime_prepare=True,
            host_instance_directory=host_path), host_path)
        self.assertEqual(compose_instance_path(Path("/state"), runtime_prepare=False,
            host_instance_directory=None), "/state")
        for unsafe in ("relative/path", "/path,with-comma", "/path:with-colon"):
            with self.subTest(path=unsafe), self.assertRaisesRegex(SystemExit, "absolute host instance path"):
                compose_instance_path(Path("/state"), runtime_prepare=True,
                    host_instance_directory=unsafe)

    def test_capability_delivery_parser_extracts_only_matching_versioned_purpose(self):
        token = "A" * 43
        document = json.dumps({"schema_version":1, "purpose":"setup", "capability":token,
            "expires_in_seconds":1800}).encode()
        self.assertEqual(capability_from_delivery(document, "prepare-setup"), token)
        for operation, altered in (
            ("prepare-setup", {"schema_version":1, "purpose":"recovery", "capability":token,
                "expires_in_seconds":900}),
            ("issue-recovery", {"schema_version":1, "purpose":"recovery", "capability":token,
                "expires_in_seconds":3600}),
            ("issue-enrolment", {"schema_version":1, "purpose":"enrolment", "capability":token,
                "expires_in_seconds":900, "debug":"secret"}),
        ):
            with self.subTest(operation=operation), self.assertRaisesRegex(SystemExit, "delivery document"):
                capability_from_delivery(json.dumps(altered).encode(), operation)

    def test_instance_lock_rejects_concurrent_owner_and_releases_stale_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with exclusive_instance_lock(root):
                with self.assertRaisesRegex(SystemExit, "another VOLT lifecycle"):
                    with exclusive_instance_lock(root):
                        pass
            self.assertEqual((root/".install.lock").stat().st_mode & 0o777, 0o600)
            with exclusive_instance_lock(root):
                pass

    def test_local_instance_load_requires_private_matching_key_and_config(self):
        import uuid
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/"instance"
            (root/"secrets").mkdir(parents=True)
            root.chmod(0o700)
            for name in SECRET_SIZES:
                (root/"secrets"/name).write_bytes(b"private-secret\n")
                (root/"secrets"/name).chmod(0o600)
            for name in ("recovery-server.crt","recovery-server.key","recovery-client.crt",
                         "recovery-client.key","recovery-ca.crt"):
                (root/"secrets"/name).write_bytes(b"private-tls\n")
                (root/"secrets"/name).chmod(0o600)
            installation=str(uuid.uuid4()); key_id=str(uuid.uuid4())
            local=local_auth_configuration(installation,key_id,"http://127.0.0.1:46180",46180,"10.240.0.1")
            config_file=root/"local-auth.json"
            config_file.write_text(json.dumps(local)+"\n"); config_file.chmod(0o600)
            (root/"secrets"/"local-auth-key").write_bytes(b"k"*32)
            (root/"secrets"/"local-auth-key").chmod(0o600)
            (root/"secrets"/"bootstrap-delivery").mkdir(mode=0o700)
            (root/"oidc.json").write_text("{}\n"); (root/"oidc.json").chmod(0o600)
            env=root/".env"; env.write_text("private\n"); env.chmod(0o600)
            metadata={"format_version":1,"initialized":True,"mode":"local","project":"volt-local-test",
                "bootstrap_principal":"","platform":"linux/amd64","image":"sha256:test",
                "image_admission":{"id":"sha256:test","platform":"linux/amd64"},
                "oidc_config_sha256":hashlib.sha256((root/"oidc.json").read_bytes()).hexdigest(),
                "installation_id":installation,
                "local_auth_config_sha256":hashlib.sha256(config_file.read_bytes()).hexdigest(),
                "ports":[46180,46181,46190],"gateway":"10.240.0.1",
                "env_sha256":hashlib.sha256(env.read_bytes()).hexdigest()}
            (root/"instance.json").write_text(json.dumps(metadata)); (root/"instance.json").chmod(0o600)
            self.assertEqual(load_instance(str(root))[1]["installation_id"],installation)
            (root/"secrets"/"local-auth-key").write_bytes(b"k"*31)
            with self.assertRaisesRegex(SystemExit,"missing or unsafe"):
                load_instance(str(root))

    def test_local_compose_config_keeps_private_mounts_and_dollar_paths_exact(self):
        import uuid
        with tempfile.TemporaryDirectory(prefix="volt local $ state ") as directory:
            root = Path(directory) / "instance with $ and spaces"
            secrets = root / "secrets"
            secrets.mkdir(parents=True)
            for name in ("uvm_db_password", "ce_db_password", "ce_admin_password", "ce_secret_key",
                         "ce_credential_key", "uvm_cursor_secret", "oidc_client_secret",
                         "oidc_sync_secret", "oidc_operator_secret", "recovery-server.crt",
                         "recovery-server.key", "recovery-ca.crt", "local-auth-key"):
                (secrets / name).write_bytes(b"private fixture\n")
            (secrets / "bootstrap-delivery").mkdir(mode=0o700)
            (root / "oidc.json").write_text("{}\n")
            local_source = str(uuid.uuid4())
            (root / "local-auth.json").write_text(json.dumps({"secret_source":{"secret_source_id":local_source}})+"\n")
            values = {
                "VOLT_PROJECT":"volt-delivery-config-test", "VOLT_INSTANCE_DIR":str(root),
                "VOLT_IMAGE":"ghcr.io/njvenis/volt@sha256:" + "a" * 64,
                "VOLT_IMAGE_ID":"sha256:" + "b" * 64, "VOLT_PLATFORM":"linux/amd64",
                "VOLT_AUTH_MODE":"local", "VOLT_LOCAL_SECRET_SOURCE_ID":local_source,
                "VOLT_OKTA_PUBLISHER_CONFIG_FILE":"", "VOLT_DEMO_ADMIN_SUBJECT":"",
                "VOLT_BOOTSTRAP_PRINCIPAL":"", "VOLT_NATIVE_GRANTABLE_ENVELOPE":"{}",
                "VOLT_OWNER_TOKEN":"owner-fixture", "VOLT_SUBNET":"10.242.0.0/28",
                "VOLT_GATEWAY":"10.242.0.1", "VOLT_HTTP_PORT":"46180",
                "VOLT_RECOVERY_PORT":"46181", "VOLT_OIDC_PORT":"46190",
                "VOLT_ALLOWED_HOSTS":"localhost,127.0.0.1",
            }
            envfile = root / ".env"
            envfile.write_text("\n".join(compose_env_line(name,value) for name,value in values.items())+"\n")
            info = {"mode":"local", "project":"volt-delivery-config-test",
                "owner_token":"owner-fixture", "image":values["VOLT_IMAGE"],
                "platform":"linux/amd64", "compose_directory":str(Path(__file__).resolve().parents[2] / "deploy/compose"),
                "env_sha256":hashlib.sha256(envfile.read_bytes()).hexdigest(),
                "okta_publisher_config_sha256":None}
            files, resolved_env, _ = resolved_compose(root, info)
            self.assertEqual(files[-2:], ["-f",str(Path(__file__).resolve().parents[2] / "deploy/compose/local.yaml")])
            self.assertEqual(resolved_env, envfile)
            result = subprocess.run(("docker", "compose", "-f", str(Path(__file__).resolve().parents[2] / "deploy/compose/compose.yaml"),
                "-f", str(Path(__file__).resolve().parents[2] / "deploy/compose/local.yaml"),
                "--env-file", str(envfile), "config", "--format", "json"),
                text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            resolved = json.loads(result.stdout)
            service = resolved["services"]["volt"]
            self.assertEqual(set(resolved["services"]), {"volt"})
            self.assertEqual(service["environment"]["UVM_AUTH_MODE"], "local")
            self.assertEqual(service["environment"]["UVM_OIDC_CONFIG_FILE"], "")
            mounts = {item["target"]:item for item in service["volumes"]}
            self.assertEqual(mounts["/run/secrets/local-auth.json"]["source"].replace("$$", "$"),
                             str(root / "local-auth.json"))
            self.assertTrue(mounts["/run/secrets/local-auth.json"]["read_only"])
            self.assertTrue(mounts["/run/secrets/local-auth-key"]["read_only"])
            self.assertFalse(mounts["/run/volt-bootstrap"].get("read_only", False))
            info.update(restore_pending=True, restore_imported=True)
            restore_files, _, _ = resolved_compose(root, info)
            self.assertEqual(restore_files[-2:], ["-f",str(Path(__file__).resolve().parents[2] / "deploy/compose/local-restore.yaml")])
            fenced = subprocess.run(("docker", "compose", *restore_files, "--env-file", str(envfile),
                "-p", info["project"], "config", "--format", "json"),
                text=True, capture_output=True, check=False)
            self.assertEqual(fenced.returncode, 0, fenced.stderr)
            self.assertEqual(json.loads(fenced.stdout)["services"]["volt"].get("ports", []), [])

    def test_okta_publisher_installer_binds_group_and_provider_mapping_without_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "private.pem"
            key.write_bytes(b"synthetic-private-key")
            key.chmod(0o600)
            publisher_config = {"schema_version": 1, "provider_id": "test-provider",
                "org_url": "https://id.example.org", "api_issuer": "https://id.example.org/oauth2/v1",
                "api_base_url": "https://id.example.org/api/v1", "client_id": "client-id",
                "app_id": "app-id", "key_id": "kid-1", "private_key_file": str(key),
                "oidc_config_file": "/ignored/host/path", "subject_by_user_id": {"00u1": "sub-1"},
                "group_ids": ["00g1"], "poll_interval_seconds": 30, "heartbeat_max_age_seconds": 120}
            path = Path(directory) / "publisher.json"
            path.write_text(json.dumps(publisher_config))
            oidc = {**config(), "group_mappings": {"00g1": {"role_ids": ["role-admin"],
                "source_scopes": []}}}
            admitted, private_key = validate_okta_publisher(path, oidc)
            self.assertEqual(private_key, b"synthetic-private-key")
            self.assertEqual(admitted["private_key_file"], "/run/uvm-g7-secrets/okta_service_private_key")
            self.assertEqual(admitted["oidc_config_file"], "/etc/volt/oidc.json")
            self.assertNotIn("password", admitted)
            with self.assertRaisesRegex(SystemExit, "group IDs"):
                validate_okta_publisher(path, {**oidc, "group_mappings": {}})

    def test_image_admission_requires_declared_platform_to_match_docker_inspect(self):
        from unittest.mock import patch
        import json
        image_id = "sha256:" + "a" * 64
        labels = {"org.volt.oidc-deployment-modes": "demo,external",
                  "org.volt.compose.source-snapshot": "sha256:" + "b" * 64,
                  "org.volt.compose-install.contract": "1",
                  "org.opencontainers.image.revision": "c" * 40,
                  "org.opencontainers.image.version": "0.2.0-demo"}
        for architecture, declared in (("arm64", "linux/arm64"), ("amd64", "linux/amd64")):
            inspected = [{"Id": image_id, "Os": "linux", "Architecture": architecture,
                          "Config": {"Labels": labels}}]
            with self.subTest(architecture=architecture), patch(
                    "deploy.compose.setup.command", return_value=json.dumps(inspected)):
                self.assertEqual(inspect_image(image_id, "demo", declared)["platform"], declared)
        with patch("deploy.compose.setup.command", return_value=json.dumps([
                {"Id": image_id, "Os": "linux", "Architecture": "amd64", "Config": {"Labels": labels}}])):
            with self.assertRaisesRegex(SystemExit, "does not match declared package platform"):
                inspect_image(image_id, "demo", "linux/arm64")
        with self.assertRaisesRegex(SystemExit, "one of the admitted package platforms"):
            inspect_image(image_id, "demo", "linux/ppc64le")

    def load(self, value: dict) -> dict:
        with patch.dict("os.environ", {"UVM_OIDC_DEPLOYMENT_MODE": "external",
                                        "UVM_OIDC_CONFIG": json.dumps(value)}):
            return load_oidc_config()

    def test_external_https_origins_are_admitted(self):
        self.assertEqual(self.load(config())["issuer"], "https://id.example.org/")

    def test_provider_role_mappings_reject_wildcards_and_empty_role_ids(self):
        for role_ids in (["*"], [""]):
            with self.subTest(role_ids=role_ids):
                value = config()
                value["group_mappings"] = {"00g-admin": {"role_ids": role_ids,
                    "source_scopes": []}}
                with self.assertRaisesRegex(RuntimeError, "mapping schema is invalid"):
                    self.load(value)

    def test_external_mode_rejects_http_provider_and_callback_origins(self):
        for field in ("issuer", "discovery_url", "callback_url"):
            with self.subTest(field=field):
                value = config(); value[field] = value[field].replace("https://", "http://")
                if field in {"issuer", "discovery_url"}:
                    value["allowed_endpoint_origins"].append("http://id.example.org")
                else:
                    value["allowed_endpoint_origins"].append("http://volt.example.org")
                with self.assertRaisesRegex(RuntimeError, "requires public HTTPS"):
                    self.load(value)

    def test_external_mode_rejects_loopback_https_provider(self):
        value = config(); value["issuer"] = "https://127.0.0.1/"
        value["allowed_endpoint_origins"][0] = "https://127.0.0.1"
        value["discovery_url"] = "https://127.0.0.1/.well-known/openid-configuration"
        with self.assertRaisesRegex(RuntimeError, "requires public HTTPS"):
            self.load(value)

    def test_external_mode_rejects_loopback_endpoint_even_with_https(self):
        value = config(); value["allowed_endpoint_origins"].append("https://localhost")
        with self.assertRaisesRegex(RuntimeError, "requires public HTTPS"):
            self.load(value)

    def test_install_host_allowlist_keeps_loopback_readiness_hosts_and_exact_external_host(self):
        self.assertEqual(allowed_host_names("Volt.Example.org"),
                         "localhost,127.0.0.1,volt.example.org")
        self.assertEqual(allowed_host_names("localhost,127.0.0.1"), "localhost,127.0.0.1")

    def test_install_host_allowlist_rejects_wildcards_ports_and_empty_values(self):
        for value in ("*", "volt.example.org:8443", "bad..example.org"):
            with self.subTest(value=value), self.assertRaisesRegex(SystemExit, "exact DNS"):
                allowed_host_names(value)

    def test_external_callback_must_use_exact_application_callback_path(self):
        import tempfile
        from pathlib import Path
        value = config(); value["callback_url"] = "https://volt.example.org/other"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oidc.json"
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(SystemExit, "exact /api/v1/auth/callback"):
                validate_external(path)

    def test_compose_interpolation_ignores_host_volt_and_compose_overrides(self):
        with patch.dict("os.environ", {"VOLT_IMAGE": "sha256:attacker", "VOLT_PROJECT": "foreign",
                                       "COMPOSE_FILE": "/tmp/foreign.yaml", "COMPOSE_PROJECT_NAME": "foreign",
                                       "PATH": "/usr/bin"}, clear=True):
            self.assertEqual(compose_environment(), {"PATH": "/usr/bin"})


if __name__ == "__main__":
    unittest.main()
