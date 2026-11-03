"""Focused safety checks for local preview ownership and configuration."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("g7_local_preview", Path(__file__).with_name("g7_local_preview.py"))
preview = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preview)


def metadata(instance="demo"):
    token = "a" * 64
    suffix = token[:16]
    return {"instance": instance, "owner_token": token,
        "container": f"volt-g7-preview-{instance}-{suffix}", "container_id": "c" * 64,
        "container_resource_id": "container-created-id", "network": f"volt-g7-preview-{instance}-{suffix}-net",
        "network_id": "n" * 64, "network_resource_id": "network-created-id",
        "volumes": {part: f"volt-g7-preview-{instance}-{suffix}-{part}" for part in ("postgres", "media", "state")},
        "volume_resource_ids": {part: f"volume-created-{part}" for part in ("postgres", "media", "state")},
        "secrets_dir": f"/tmp/unused/{instance}/secrets", "lifecycle_state": "established"}


def write_instance(root: Path, info: dict) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    secrets_dir = root / "secrets"
    secrets_dir.mkdir(exist_ok=True)
    info["secrets_dir"] = str(secrets_dir)
    (root / "oidc.json").write_text("{}")
    (root / "operator-link.json").write_text("{}")
    metadata_path = root / "instance.json"
    metadata_path.write_text(json.dumps(info))
    return metadata_path


class LocalPreviewSafetyTests(unittest.TestCase):
    def test_instance_name_is_safe_and_state_root_scoped(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
            self.assertEqual(preview.state_dir("demo"), Path(temp) / "volt/g7-preview/demo")
            for bad in ("../demo", "a/b", "demo space", ""):
                with self.subTest(bad=bad), self.assertRaises(SystemExit):
                    preview.state_dir(bad)

    def test_symlinked_xdg_base_is_allowed_and_instance_starts_unestablished(self):
        with tempfile.TemporaryDirectory() as temp:
            real_base = Path(temp) / "real-state"
            real_base.mkdir()
            linked_base = Path(temp) / "linked-state"
            linked_base.symlink_to(real_base, target_is_directory=True)
            with patch.dict(os.environ, {"XDG_STATE_HOME": str(linked_base)}), \
                 patch.object(preview, "run", side_effect=lambda *a, capture=False: "source-sha" if a[:2] == ("git", "rev-parse") else ""), \
                 patch.object(preview, "make_tls"):
                preview.initialize(type("Args", (), {"instance": "demo", "api_port": 8180, "oidc_port": 8190})())
                root, info = preview.load("demo")
            self.assertEqual(root, (real_base / "volt/g7-preview/demo").resolve())
            self.assertEqual(info["lifecycle_state"], "initializing")

    def test_each_initialization_gets_distinct_resource_names_and_ownership_token(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            infos = []
            for base in (first, second):
                with patch.dict(os.environ, {"XDG_STATE_HOME": base}), \
                     patch.object(preview, "run", side_effect=lambda *a, capture=False: "source-sha" if a[:2] == ("git", "rev-parse") else ""), \
                     patch.object(preview, "make_tls"):
                    args = type("Args", (), {"instance": "demo", "api_port": 8180, "oidc_port": 8190})()
                    preview.initialize(args)
                    _root, info = preview.load("demo")
                    infos.append(info)
            self.assertNotEqual(infos[0]["owner_token"], infos[1]["owner_token"])
            self.assertNotEqual(infos[0]["container"], infos[1]["container"])
            self.assertTrue(set(infos[0]["volumes"].values()).isdisjoint(infos[1]["volumes"].values()))

    def test_generated_secret_is_private(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "secret"
            value = preview.secret(path, 12)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.read_text().strip(), value)
            self.assertGreaterEqual(len(value), 16)

    def test_oidc_and_private_ingress_configuration_are_exact(self):
        config = preview.oidc_configuration("http://127.0.0.1:8180", "http://127.0.0.1:8190")
        self.assertEqual(config["issuer"], "http://127.0.0.1:8190")
        self.assertEqual(config["discovery_url"], "http://127.0.0.1:9000/.well-known/openid-configuration")
        self.assertEqual(config["callback_url"], "http://127.0.0.1:8180/api/v1/auth/callback")
        self.assertEqual(preview.ingress_peer_cidrs("172.22.0.1"), ("127.0.0.1/32", "172.22.0.1/32"))
        self.assertEqual(preview.ingress_hostnames(), "127.0.0.1,localhost")

    def test_preview_grant_envelope_has_exact_synthetic_source(self):
        envelope = preview.preview_grantable_envelope()
        self.assertEqual(envelope["source_scopes"], [{"source_family": "local",
            "source_account_id": "volt-local-preview", "scope_key": "all"}])
        self.assertEqual(envelope["target_scope"]["source_families"], ["local"])
        self.assertEqual(envelope["limits"]["allowed_environments"], ["*"])
        self.assertEqual(envelope["limits"]["allowed_service_ids"], ["*"])

    def test_foreign_volume_refused_before_build_or_any_mutation(self):
        info = metadata()
        info["container_id"] = None
        info["network_id"] = None
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
            root = preview.state_dir("demo"); write_instance(root, info)
            args = type("Args", (), {"instance": "demo", "image": None})()
            def inspect(command, **kwargs):
                if command[1] == "inspect" and command[2] == "--format":
                    return subprocess.CompletedProcess(command, 1, "", "Error: No such object: absent")
                if command[1:3] == ("network", "inspect"):
                    return subprocess.CompletedProcess(command, 1, "", "Error: No such network: absent")
                if command[1:3] == ("volume", "inspect"):
                    return subprocess.CompletedProcess(command, 0, "foreign-token|foreign-created-id\n", "")
                raise AssertionError(command)
            with patch.object(preview.subprocess, "run", side_effect=inspect), patch.object(preview, "run") as docker_run:
                with self.assertRaisesRegex(SystemExit, "refusing preview volume"):
                    preview.start(args)
            docker_run.assert_not_called()

    def test_replaced_container_refused_before_stop_mutation(self):
        info = metadata()
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
            root = preview.state_dir("demo"); write_instance(root, info)
            args = type("Args", (), {"instance": "demo"})()
            def inspect(command, **kwargs):
                if command[1] == "inspect" and command[2] == "--format":
                    return subprocess.CompletedProcess(command, 0, f"{'d'*64}|{info['owner_token']}|{info['container_resource_id']}\n", "")
                raise AssertionError(command)
            with patch.object(preview.subprocess, "run", side_effect=inspect), patch.object(preview, "run") as docker_run:
                with self.assertRaisesRegex(SystemExit, "exact created container ID"):
                    preview.docker_for(args, "stop")
            docker_run.assert_not_called()

    def test_destroy_preflights_every_target_before_removing_anything(self):
        info = metadata()
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
            root = preview.state_dir("demo"); write_instance(root, info)
            args = type("Args", (), {"instance": "demo"})()
            def inspect(command, **kwargs):
                if command[1] == "inspect" and command[2] == "--format":
                    return subprocess.CompletedProcess(command, 1, "", "Error: No such object: absent")
                if command[1:3] == ("network", "inspect"):
                    return subprocess.CompletedProcess(command, 0, f"{info['network_id']}|{info['owner_token']}|{info['network_resource_id']}\n", "")
                if command[1:3] == ("volume", "inspect"):
                    name = command[-1]
                    part = next(k for k,v in info["volumes"].items() if v == name)
                    token = "foreign-token" if part == "media" else info["owner_token"]
                    return subprocess.CompletedProcess(command, 0, f"{token}|{info['volume_resource_ids'][part]}\n", "")
                raise AssertionError(command)
            with patch.object(preview.subprocess, "run", side_effect=inspect), patch.object(preview, "run") as docker_run:
                with self.assertRaisesRegex(SystemExit, "refusing preview volume"):
                    preview.destroy(args)
            docker_run.assert_not_called()
            self.assertTrue(root.exists())

    def test_symlinked_instance_alias_is_rejected_before_any_io_or_mutation(self):
        info = metadata("original")
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
            original = preview.state_dir("original")
            metadata_path = write_instance(original, info)
            original_bytes = metadata_path.read_bytes()
            alias = preview.state_dir("alias")
            alias.parent.mkdir(parents=True, exist_ok=True)
            alias.symlink_to(original, target_is_directory=True)
            args = type("Args", (), {"instance": "alias"})()
            with patch.object(preview.subprocess, "run") as docker_inspect, patch.object(preview, "run") as docker_mutation:
                with self.assertRaisesRegex(SystemExit, "instance directory is a symlink"):
                    preview.destroy(args)
            docker_inspect.assert_not_called()
            docker_mutation.assert_not_called()
            self.assertEqual(metadata_path.read_bytes(), original_bytes)
            self.assertTrue(original.is_dir())

    def test_metadata_instance_mismatch_is_rejected_before_any_docker_io(self):
        info = metadata("other")
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
            root = preview.state_dir("demo")
            metadata_path = write_instance(root, info)
            before = metadata_path.read_bytes()
            args = type("Args", (), {"instance": "demo"})()
            with patch.object(preview.subprocess, "run") as docker_inspect, patch.object(preview, "run") as docker_mutation:
                with self.assertRaisesRegex(SystemExit, "stored instance does not match"):
                    preview.destroy(args)
            docker_inspect.assert_not_called()
            docker_mutation.assert_not_called()
            self.assertEqual(metadata_path.read_bytes(), before)

    def test_symlinked_metadata_is_rejected_before_any_docker_io(self):
        info = metadata("original")
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
            original = preview.state_dir("original")
            original_metadata = write_instance(original, info)
            root = preview.state_dir("demo")
            root.mkdir(parents=True)
            (root / "instance.json").symlink_to(original_metadata)
            args = type("Args", (), {"instance": "demo"})()
            with patch.object(preview.subprocess, "run") as docker_inspect, patch.object(preview, "run") as docker_mutation:
                with self.assertRaisesRegex(SystemExit, "instance.json is a symlink"):
                    preview.destroy(args)
            docker_inspect.assert_not_called()
            docker_mutation.assert_not_called()
            self.assertTrue(original_metadata.exists())

    def test_private_reference_outside_instance_root_is_rejected_before_docker_io(self):
        info = metadata()
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
            root = preview.state_dir("demo")
            metadata_path = write_instance(root, info)
            info["secrets_dir"] = temp
            metadata_path.write_text(json.dumps(info))
            before = metadata_path.read_bytes()
            args = type("Args", (), {"instance": "demo"})()
            with patch.object(preview.subprocess, "run") as docker_inspect, patch.object(preview, "run") as docker_mutation:
                with self.assertRaisesRegex(SystemExit, "private files are outside the instance root"):
                    preview.destroy(args)
            docker_inspect.assert_not_called()
            docker_mutation.assert_not_called()
            self.assertEqual(metadata_path.read_bytes(), before)

    def test_missing_established_resources_refuse_start_and_restart_without_rebinding(self):
        for missing_kind, missing_part in (("container", None), ("network", None), ("volume", "postgres")):
            with self.subTest(missing_kind=missing_kind, missing_part=missing_part), \
                    tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
                info = metadata()
                root = preview.state_dir("demo")
                metadata_path = write_instance(root, info)
                before = metadata_path.read_bytes()
                if missing_kind == "container":
                    missing_name = info["container"]
                elif missing_kind == "network":
                    missing_name = info["network"]
                else:
                    missing_name = info["volumes"][missing_part]

                def inspect(command, **kwargs):
                    if command[-1] == missing_name:
                        error = "No such object" if missing_kind == "container" else f"no such {missing_kind}"
                        return subprocess.CompletedProcess(command, 1, "", f"Error: {error}: missing")
                    if command[1] == "inspect" and command[2] == "--format":
                        return subprocess.CompletedProcess(command, 0,
                            f"{info['container_id']}|{info['owner_token']}|{info['container_resource_id']}\n", "")
                    if command[1:3] == ("network", "inspect"):
                        return subprocess.CompletedProcess(command, 0,
                            f"{info['network_id']}|{info['owner_token']}|{info['network_resource_id']}\n", "")
                    if command[1:3] == ("volume", "inspect"):
                        part = next(k for k, value in info["volumes"].items() if value == command[-1])
                        return subprocess.CompletedProcess(command, 0,
                            f"{info['owner_token']}|{info['volume_resource_ids'][part]}\n", "")
                    raise AssertionError(command)

                args = type("Args", (), {"instance": "demo", "image": None})()
                for operation in ("start", "restart"):
                    with self.subTest(operation=operation), \
                            patch.object(preview.subprocess, "run", side_effect=inspect), \
                            patch.object(preview, "run") as docker_mutation:
                        with self.assertRaisesRegex(SystemExit, "missing owned resources"):
                            if operation == "start":
                                preview.start(args)
                            else:
                                preview.docker_for(args, "restart")
                        docker_mutation.assert_not_called()
                        self.assertEqual(metadata_path.read_bytes(), before)

    def test_explicit_destroy_removes_only_surviving_verified_resources(self):
        info = metadata()
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
            root = preview.state_dir("demo")
            metadata_path = write_instance(root, info)
            calls = []

            def inspect(command, **kwargs):
                calls.append(tuple(command))
                if command[1] == "inspect" and command[2] == "--format":
                    return subprocess.CompletedProcess(command, 1, "", "Error: no such object: container")
                if command[1:3] == ("network", "inspect"):
                    return subprocess.CompletedProcess(command, 1, "", "Error: no such network: network")
                if command[1:3] == ("volume", "inspect"):
                    part = next(k for k, value in info["volumes"].items() if value == command[-1])
                    if part == "postgres":
                        return subprocess.CompletedProcess(command, 1, "", "Error: no such volume: postgres")
                    return subprocess.CompletedProcess(command, 0,
                        f"{info['owner_token']}|{info['volume_resource_ids'][part]}\n", "")
                raise AssertionError(command)

            with patch.object(preview.subprocess, "run", side_effect=inspect), \
                 patch.object(preview, "run") as docker_mutation:
                preview.destroy(type("Args", (), {"instance": "demo"})())
            removed = [call.args for call in docker_mutation.call_args_list]
            self.assertEqual(removed, [("docker", "volume", "rm", info["volumes"]["media"]),
                ("docker", "volume", "rm", info["volumes"]["state"])])
            self.assertFalse(root.exists())
            self.assertGreaterEqual(len(calls), 5)


if __name__ == "__main__":
    unittest.main()
