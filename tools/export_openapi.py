#!/usr/bin/env python3
"""Export the application's API schema using only synthetic, disposable state.

This constructs routes; it does not start a server or exercise external services.
Ambient deployment configuration is excluded before importing the app factory.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import importlib
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import uuid
from unittest.mock import patch


def _app_schema(mode: str, directory: Path) -> dict:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("UVM_")}
    environment["UVM_AUTH_MODE"] = mode
    environment["UVM_API_CURSOR_SECRET"] = "synthetic-openapi-export-not-a-credential"
    environment["UVM_INGRESS_ALLOWED_PEER_CIDRS"] = "127.0.0.0/8"
    environment["UVM_INGRESS_ALLOWED_HOSTS"] = "127.0.0.1"
    with patch.dict(os.environ, environment, clear=True):
        import sqlalchemy as sa
        from uvm.persistence.schema import uvm_metadata

        # Register all additive table declarations before making the disposable
        # SQLite database. This data is never used for request admission.
        for module in (
            "observation", "lineage", "alias", "assessment", "deadline_reference",
            "auth", "native_authority", "connector", "incident", "ingestion",
            "exception_sla", "backup_settings", "health", "observer_settings",
            "engine_operation", "scalar", "g4", "metrics",
        ):
            try:
                importlib.import_module(f"uvm.persistence.{module}_schema")
            except ModuleNotFoundError as exc:
                if exc.name != f"uvm.persistence.{module}_schema":
                    raise

        if mode in {"local", "oidc"}:
            secret_path = directory / f"{mode}-secret"
            secret_path.write_text("synthetic-openapi-export-secret", encoding="utf-8")
            secret_path.chmod(0o600)
        if mode == "local":
            key_path = directory / "local-key"
            key_path.write_bytes(secrets.token_bytes(32))
            key_path.chmod(0o600)
            config = {
                "schema_version": 1,
                "installation_id": str(uuid.uuid4()),
                "public_origin": "http://127.0.0.1",
                "secret_source": {"kind": "encrypted_local_v1",
                    "secret_source_id": str(uuid.uuid4()), "key_path": str(key_path)},
                "bootstrap_delivery": {"kind": "private_file", "path": str(directory / "delivery")},
                "session_policy": {"ttl_seconds": 3600},
                "trusted_ingress": {"mode": "loopback", "allowed_hosts": ["127.0.0.1"],
                    "allowed_peer_cidrs": ["127.0.0.0/8"]},
            }
            config_path = directory / "local-auth.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            config_path.chmod(0o600)
            environment["UVM_LOCAL_AUTH_CONFIG_FILE"] = str(config_path)
        elif mode == "oidc":
            origin = "https://identity.example.invalid"
            config = {
                "schema_version": 1, "provider_id": "openapi-export",
                "issuer": origin, "discovery_url": origin + "/.well-known/openid-configuration",
                "client_id": "synthetic", "callback_url": "https://app.example.invalid/callback",
                "client_secret_file": str(secret_path), "sync_secret_file": str(secret_path),
                "operator_secret_file": str(secret_path), "operator_actor_id": "openapi-export",
                "allowed_algorithms": ["RS256"],
                "allowed_endpoint_origins": [origin, "https://app.example.invalid"],
                "source_scope_ceilings": [], "group_mappings": {}, "mapping_revision": 1,
                "session_ttl_seconds": 3600, "heartbeat_max_age_seconds": 3600,
            }
            environment["UVM_OIDC_CONFIG"] = json.dumps(config)

        with patch.dict(os.environ, environment, clear=True):
            from uvm.api.app import create_app
            engine = sa.create_engine("sqlite+pysqlite:///:memory:")
            try:
                uvm_metadata.create_all(engine)
                app = create_app(
                    engine,
                    principals={},
                    cursor_secret="synthetic-openapi-export-not-a-credential",
                    utc_now=lambda: datetime(2026, 1, 1, tzinfo=UTC),
                )
                return app.openapi()
            finally:
                engine.dispose()


def _merge_schema_alternative(existing: dict, incoming: dict, existing_modes: list[str], mode: str) -> dict:
    variants = []
    if existing.get("anyOf"):
        variants.extend(existing["anyOf"])
    else:
        variants.append({**existing, "x-uvm-auth-modes": existing_modes})
    candidate = {**incoming, "x-uvm-auth-modes": [mode]}
    for variant in variants:
        if {k: v for k, v in variant.items() if k != "x-uvm-auth-modes"} == incoming:
            variant["x-uvm-auth-modes"] = sorted(set(variant.get("x-uvm-auth-modes", [])) | {mode})
            break
    else:
        variants.append(candidate)
    if len(variants) == 1:
        return {k: v for k, v in variants[0].items() if k != "x-uvm-auth-modes"}
    return {"anyOf": variants}


def _merge_operation(existing: dict, incoming: dict, mode: str) -> dict:
    previous_modes = list(existing.get("x-uvm-auth-modes", []))
    merged = dict(existing)
    merged["x-uvm-auth-modes"] = sorted(set(previous_modes) | {mode})
    for container in ("responses", "requestBody"):
        if container not in incoming:
            continue
        if container == "requestBody":
            prior, new = merged.get(container), incoming[container]
            if prior is None:
                merged[container] = new
            elif prior != new:
                prior = dict(prior)
                for content_type, content in new.get("content", {}).items():
                    old_content = prior.setdefault("content", {}).get(content_type)
                    if old_content is None:
                        prior["content"][content_type] = content
                    else:
                        old_content = dict(old_content)
                        old_content["schema"] = _merge_schema_alternative(
                            old_content.get("schema", {}), content.get("schema", {}), previous_modes, mode)
                        prior["content"][content_type] = old_content
                merged[container] = prior
            continue
        responses = dict(merged.get("responses", {}))
        for status, response in incoming[container].items():
            if status not in responses:
                responses[status] = response
                continue
            old_response, combined = dict(responses[status]), dict(responses[status])
            combined["content"] = dict(old_response.get("content", {}))
            for content_type, content in response.get("content", {}).items():
                old_content = combined["content"].get(content_type)
                if old_content is None:
                    combined["content"][content_type] = content
                else:
                    old_content = dict(old_content)
                    old_content["schema"] = _merge_schema_alternative(
                        old_content.get("schema", {}), content.get("schema", {}), previous_modes, mode)
                    combined["content"][content_type] = old_content
            responses[status] = combined
        merged[container] = responses
    return merged


def export_schema() -> dict:
    # Merge route declarations from the supported runtime modes. Admission is
    # not changed: each exported route is still selected by the deployed mode.
    with tempfile.TemporaryDirectory(prefix="volt-openapi-") as temporary:
        directory = Path(temporary)
        bearer = _app_schema("bearer", directory)
        oidc = _app_schema("oidc", directory)
        local = _app_schema("local", directory)
    schema = dict(bearer)
    schema["paths"] = json.loads(json.dumps(bearer.get("paths", {})))
    components = {}
    mode_schemas = (("bearer", bearer), ("oidc", oidc), ("local", local))
    for item in (bearer, oidc, local):
        for name, value in item.get("components", {}).items():
            components.setdefault(name, {}).update(value)
    if components:
        schema["components"] = components
    for mode, item in mode_schemas:
        for path, path_item in item.get("paths", {}).items():
            exported_path = schema["paths"].setdefault(path, {})
            for method, operation in path_item.items():
                if method not in {"get", "put", "post", "delete", "options", "head", "patch", "trace"}:
                    continue
                exported_operation = exported_path.get(method)
                exported_path[method] = (_merge_operation(exported_operation, operation, mode)
                    if exported_operation is not None else {**operation, "x-uvm-auth-modes": [mode]})
    return schema


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(export_schema(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    main()
