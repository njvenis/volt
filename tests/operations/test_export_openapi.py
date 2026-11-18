"""The published OpenAPI document covers each supported auth-mode route set."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "volt_export_openapi", ROOT / "tools" / "export_openapi.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def schema_accepts(schema, value):
    # JSON Schema is a verification dependency, separate from runtime packages.
    # Keep credential responses in memory and never echo validator input.
    result = subprocess.run([os.environ.get("UVM_JSONSCHEMA_PYTHON", "python3"), "-c",
        "import json,sys; from jsonschema import Draft202012Validator; "
        "s,v=json.load(sys.stdin); sys.exit(0 if Draft202012Validator(s).is_valid(v) else 1)"],
        input=json.dumps([schema, value]), text=True, capture_output=True, timeout=15)
    if result.returncode not in (0, 1) or result.stderr:
        raise RuntimeError("JSON Schema verification dependency unavailable")
    return result.returncode == 0


class OpenAPIModeExportTests(unittest.TestCase):
    def test_combined_schema_includes_local_oidc_and_base_commands(self):
        schema = MODULE.export_schema()
        paths = schema["paths"]
        self.assertIn("/api/v1/auth/setup/claim", paths)
        self.assertIn("/api/v1/auth/local/login", paths)
        self.assertIn("/api/v1/auth/session", paths)
        self.assertIn("/api/v1/auth/login", paths)
        self.assertIn("/api/v1/assessment/commands", paths)
        self.assertIn("/api/v1/assessment/commands/{command_id}/abandon", paths)
        self.assertIn("/api/v1/deployment", paths)
        claim = paths["/api/v1/auth/setup/claim"]["post"]
        body_schema = claim["requestBody"]["content"]["application/json"]["schema"]
        self.assertEqual(set(body_schema["properties"]),
            {"capability", "username", "display_name", "password"})
        session_schema = paths["/api/v1/auth/session"]["get"]["responses"]["200"][
            "content"]["application/json"]["schema"]
        self.assertEqual(paths["/api/v1/auth/session"]["get"]["x-uvm-auth-modes"],
            ["local", "oidc"])
        self.assertEqual(len(session_schema["anyOf"]), 2)
        local_response = next(item for item in session_schema["anyOf"]
            if "local" in item["x-uvm-auth-modes"])
        local_model = schema["components"]["schemas"][local_response["$ref"].rsplit("/", 1)[-1]]
        self.assertIn("protected_admin", local_model["properties"])
        oidc_response = next(item for item in session_schema["anyOf"]
            if "oidc" in item["x-uvm-auth-modes"])
        self.assertTrue(oidc_response["$ref"].endswith("/OIDCSessionDTO"))
        deployment_schema = paths["/api/v1/deployment"]["get"]["responses"]["200"][
            "content"]["application/json"]["schema"]
        self.assertIn("connector_registry_revision", schema["components"]["schemas"][
            deployment_schema["$ref"].rsplit("/", 1)[-1]]["properties"])

    def test_registration_and_abandonment_export_strict_runtime_envelopes(self):
        paths = MODULE.export_schema()["paths"]
        command_schema = paths["/api/v1/assessment/commands"]["post"]["requestBody"][
            "content"]["application/json"]["schema"]
        registration, legacy = command_schema["oneOf"]
        self.assertFalse(registration["additionalProperties"])
        self.assertEqual(registration["properties"]["target_id"]["const"],
            "00000000-0000-0000-0000-000000000000")
        self.assertEqual(set(registration["required"]), set(registration["properties"]))
        self.assertTrue(legacy["additionalProperties"])
        malformed = {"command_id":"00000000-0000-4000-8000-000000000001",
            "action":"connector.binding.register", "target_id":"00000000-0000-0000-0000-000000000000",
            "membership_ids":[], "expected_revisions":{}, "payload":{}}
        self.assertFalse(schema_accepts(command_schema, malformed))
        malformed["action"] = "principal.update"
        self.assertTrue(schema_accepts(command_schema, malformed))
        abandon_schema = paths["/api/v1/assessment/commands/{command_id}/abandon"]["post"][
            "requestBody"]["content"]["application/json"]["schema"]
        self.assertFalse(abandon_schema["additionalProperties"])
        variants=abandon_schema["properties"]["command"]["oneOf"]
        self.assertEqual({item["properties"]["action"]["const"] for item in variants},
            {"connector.binding.register","connector.recovery.clearance.apply"})
        self.assertTrue(all(item["additionalProperties"] is False for item in variants))


if __name__ == "__main__":
    unittest.main()
