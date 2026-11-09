from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from uvm.auth.service import load_oidc_config
from deploy.compose.setup import allowed_host_names, compose_environment, validate_external


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
