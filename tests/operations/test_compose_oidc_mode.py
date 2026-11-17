from __future__ import annotations

import json
import hashlib
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from uvm.auth.service import load_oidc_config
from deploy.compose.setup import (allowed_host_names, compose_environment, demo_identity,
                                  demo_password_verifier, inspect_image, validate_external,
                                  validate_okta_publisher, compose_files, identity_secret_sources,
                                  validate_identity_secret_mounts, resolved_compose)


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
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/".env").write_text("test\n")
            info={**info,"env_sha256":hashlib.sha256((root/".env").read_bytes()).hexdigest()}
            with patch("deploy.compose.setup.command") as compose_command:
                with self.assertRaisesRegex(SystemExit,"demo-admin-credentials"):
                    resolved_compose(root,info)
                compose_command.assert_not_called()

    def test_wrong_mode_identity_secret_mounts_are_rejected(self):
        for mode, forbidden in (("demo","okta_service_private_key"),("external","demo-admin-credentials")):
            with self.subTest(mode=mode), self.assertRaisesRegex(SystemExit,"wrong deployment mode"):
                validate_identity_secret_mounts({"secrets":{forbidden:{"file":"/private/source"}}},
                    {"secrets":[{"source":forbidden,"target":f"/run/secrets/{forbidden}"}]},{},
                    {"mode":mode})

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
