"""Focused safety checks for local preview ownership and configuration."""
from __future__ import annotations

import importlib.util
import json
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
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
                    return subprocess.CompletedProcess(command, 0, f"{'f'*64}|{info['owner_token']}|{info['container_resource_id']}\n", "")
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


    def test_no_build_requires_complete_admission_metadata_without_docker_io(self):
        complete = {"no_build": True, "image": None, "expected_image_id": "sha256:" + "a" * 64,
            "expected_image_source_revision": "b" * 40, "expected_image_version": "local-preview",
            "expected_platform": "linux/amd64"}
        for missing in ("expected_image_id", "expected_image_source_revision", "expected_image_version", "expected_platform"):
            with self.subTest(missing=missing):
                values = dict(complete); values[missing] = None
                args = type("Args", (), values)()
                with patch.object(preview.subprocess, "run") as docker_read, patch.object(preview, "run") as command:
                    with self.assertRaisesRegex(SystemExit, "requires --expected-image-id"):
                        preview.start(args)
                docker_read.assert_not_called()
                command.assert_not_called()

    def test_invalid_no_build_admission_arguments_are_rejected_before_docker_io(self):
        base = {"no_build": True, "image": None, "expected_image_id": "sha256:" + "a" * 64,
            "expected_image_source_revision": "b" * 40, "expected_image_version": "local-preview",
            "expected_platform": "linux/amd64"}
        variants = [
            ("short image id", {"expected_image_id": "sha256:abc"}, "full sha256 ID"),
            ("short source revision", {"expected_image_source_revision": "deadbeef"}, "full commit SHA"),
            ("unsafe version", {"expected_image_version": "local-preview\nInjected"}, "version metadata is invalid"),
            ("unsupported platform", {"expected_platform": "linux/arm64"}, "supported platform must be linux/amd64"),
            ("mutable tag option", {"image": "volt:mutable"}, "cannot be combined with --no-build"),
        ]
        for name, override, reason in variants:
            with self.subTest(name=name):
                values = dict(base); values.update(override)
                args = type("Args", (), values)()
                with patch.object(preview.subprocess, "run") as docker_read, patch.object(preview, "run") as command:
                    with self.assertRaisesRegex(SystemExit, reason):
                        preview.start(args)
                docker_read.assert_not_called()
                command.assert_not_called()

    def _run_no_build_start(self, image_result, *, expected_id=None):
        support_revision = "c" * 40
        image_source_revision = "b" * 40
        expected_id = expected_id or ("sha256:" + "a" * 64)
        info = metadata()
        info.update({"container_id": None, "network_id": None, "lifecycle_state": "initializing",
            "source_revision": support_revision, "helper_revision": support_revision,
            "api_port": 8580, "oidc_port": 8590})
        docker_commands = []
        mutations = []
        timeline = []
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
            root = preview.state_dir("demo")
            metadata_path = write_instance(root, info)
            before = metadata_path.read_bytes()
            args = type("Args", (), {"instance": "demo", "image": None, "no_build": True,
                "expected_image_id": expected_id, "expected_image_source_revision": image_source_revision,
                "expected_image_version": "local-preview", "expected_platform": "linux/amd64"})()
            container_created = False
            network_created = False
            created_volumes = set()
            image_inspects = 0

            def docker_inspect(command, **kwargs):
                nonlocal image_inspects
                command = tuple(command)
                docker_commands.append(command)
                timeline.append(command)
                if command[1:3] == ("image", "inspect"):
                    image_inspects += 1
                    if isinstance(image_result, subprocess.CompletedProcess):
                        return image_result
                    return subprocess.CompletedProcess(command, 0, json.dumps([image_result]), "")
                if command[1:3] == ("inspect", "--format"):
                    if command[-1] == info["container"]:
                        if container_created:
                            return subprocess.CompletedProcess(command, 0,
                                f"{'f'*64}|{info['owner_token']}|{info['container_resource_id']}\n", "")
                        return subprocess.CompletedProcess(command, 1, "", "no such object")
                if command[1:3] == ("network", "inspect"):
                    if network_created:
                        return subprocess.CompletedProcess(command, 0,
                            f"{'e'*64}|{info['owner_token']}|{info['network_resource_id']}\n", "")
                    return subprocess.CompletedProcess(command, 1, "", "no such network")
                if command[1:3] == ("volume", "inspect"):
                    name = command[-1]
                    part = next((key for key, value in info["volumes"].items() if value == name), None)
                    if part in created_volumes:
                        return subprocess.CompletedProcess(command, 0,
                            f"{info['owner_token']}|{info['volume_resource_ids'][part]}\n", "")
                    return subprocess.CompletedProcess(command, 1, "", "no such volume")
                raise AssertionError(command)

            def helper_run(*command, capture=False):
                nonlocal container_created, network_created
                command = tuple(command)
                if command[0] == "git":
                    return support_revision if command[1:3] == ("rev-parse", "HEAD") else ""
                if command[0] != "docker":
                    raise AssertionError(command)
                timeline.append(command)
                if command[1:3] == ("network", "create"):
                    self.assertEqual(json.loads(metadata_path.read_text()).get("image_binding"), {
                        "id": expected_id, "revision": image_source_revision,
                        "version": "local-preview", "platform": "linux/amd64"})
                    mutations.append(command); network_created = True; return ""
                if command[1:3] == ("volume", "create"):
                    mutations.append(command)
                    created_volumes.add(next(k for k, value in info["volumes"].items() if value == command[-1]))
                    return ""
                if command[1] == "run":
                    mutations.append(command)
                    self.assertEqual(image_inspects, 2, "image was not rechecked immediately before launch")
                    container_created = True
                    return "f" * 64
                if command[1:3] == ("network", "inspect") and command[3] == "--format":
                    if command[4] == "{{.Id}}": return "e" * 64
                    if command[4] == "{{(index .IPAM.Config 0).Gateway}}": return "172.19.0.1"
                if command[1:3] == ("inspect", "--format") and command[3] == "{{.Image}}":
                    return expected_id
                raise AssertionError(command)

            with patch.object(preview.subprocess, "run", side_effect=docker_inspect), \
                 patch.object(preview, "run", side_effect=helper_run), redirect_stdout(io.StringIO()):
                preview.start(args)
            return {"docker_commands": docker_commands, "mutations": mutations, "timeline": timeline,
                "metadata": json.loads(metadata_path.read_text()), "before": before,
                "after": metadata_path.read_bytes(), "expected_id": expected_id,
                "image_source_revision": image_source_revision, "helper_revision": support_revision,
                "image_inspects": image_inspects}

    def test_no_build_wrong_or_missing_image_metadata_fails_before_any_mutation(self):
        expected_id = "sha256:" + "a" * 64
        expected_revision = "b" * 40
        good = {"Id": expected_id, "Os": "linux", "Architecture": "amd64", "Config": {"Labels": {
            "org.opencontainers.image.revision": expected_revision,
            "org.opencontainers.image.version": "local-preview"}}}
        cases = [
            ("image ID mismatch", {**good, "Id": "sha256:" + "f" * 64}, "immutable image ID mismatch"),
            ("source revision mismatch", {**good, "Config": {"Labels": {
                "org.opencontainers.image.revision": "d" * 40,
                "org.opencontainers.image.version": "local-preview"}}}, "source revision label mismatch"),
            ("version mismatch", {**good, "Config": {"Labels": {
                "org.opencontainers.image.revision": expected_revision,
                "org.opencontainers.image.version": "other"}}}, "version label mismatch"),
            ("platform mismatch", {**good, "Architecture": "arm64"}, "platform metadata mismatch"),
            ("missing metadata", {"Id": expected_id, "Os": "linux", "Architecture": "amd64", "Config": {}}, "metadata is missing or malformed"),
            ("missing image", subprocess.CompletedProcess(("docker", "image", "inspect"), 1, "", "not found"), "image ID is unavailable"),
        ]
        for name, result, reason in cases:
            with self.subTest(name=name):
                support_revision = "c" * 40
                info = metadata()
                info.update({"container_id": None, "network_id": None, "lifecycle_state": "initializing",
                    "source_revision": support_revision, "helper_revision": support_revision})
                with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
                    root = preview.state_dir("demo"); metadata_path = write_instance(root, info)
                    before = metadata_path.read_bytes()
                    args = type("Args", (), {"instance": "demo", "image": None, "no_build": True,
                        "expected_image_id": expected_id, "expected_image_source_revision": expected_revision,
                        "expected_image_version": "local-preview", "expected_platform": "linux/amd64"})()
                    docker_commands = []
                    def inspect(command, **kwargs):
                        command = tuple(command); docker_commands.append(command)
                        if command[1:3] == ("image", "inspect"):
                            if isinstance(result, subprocess.CompletedProcess): return result
                            return subprocess.CompletedProcess(command, 0, json.dumps([result]), "")
                        if command[1:3] == ("inspect", "--format"):
                            return subprocess.CompletedProcess(command, 1, "", "no such object")
                        if command[1:3] == ("network", "inspect"):
                            return subprocess.CompletedProcess(command, 1, "", "no such network")
                        if command[1:3] == ("volume", "inspect"):
                            return subprocess.CompletedProcess(command, 1, "", "no such volume")
                        raise AssertionError(command)
                    def git_only(*command, capture=False):
                        if command[0] == "git": return support_revision if command[1:3] == ("rev-parse", "HEAD") else ""
                        raise AssertionError(f"unexpected mutation command: {command}")
                    with patch.object(preview.subprocess, "run", side_effect=inspect), \
                         patch.object(preview, "run", side_effect=git_only):
                        with self.assertRaisesRegex(SystemExit, reason):
                            preview.start(args)
                    self.assertEqual(metadata_path.read_bytes(), before)
                    self.assertTrue(all(command[1] in {"inspect", "image", "network", "volume"} and
                        not (command[1] in {"network", "volume"} and len(command) > 2 and command[2] != "inspect")
                        for command in docker_commands), docker_commands)
                    self.assertFalse(any(command[1] in {"build", "run", "create", "start", "rm"}
                        for command in docker_commands))

    def test_no_build_launches_by_admitted_id_with_distinct_helper_revision(self):
        image_id = "sha256:" + "a" * 64
        image = {"Id": image_id, "Os": "linux", "Architecture": "amd64", "Config": {"Labels": {
            "org.opencontainers.image.revision": "b" * 40,
            "org.opencontainers.image.version": "local-preview"}}}
        result = self._run_no_build_start(image)
        run_command = next(command for command in result["mutations"] if command[1] == "run")
        self.assertEqual(run_command[-1], image_id)
        self.assertFalse(any(command[1] == "build" for command in result["mutations"]))
        self.assertEqual(result["image_inspects"], 2)
        self.assertEqual(result["metadata"]["source_revision"], result["helper_revision"])
        self.assertEqual(result["metadata"]["helper_revision"], result["helper_revision"])
        self.assertNotEqual(result["metadata"]["helper_revision"], result["image_source_revision"])
        self.assertEqual(result["metadata"]["image_source_revision"], "b" * 40)
        self.assertEqual(result["metadata"]["image_id"], image_id)
        self.assertEqual(result["metadata"]["image_mode"], "loaded-image")
        timeline = result["timeline"]
        first_image_inspect = next(i for i, command in enumerate(timeline) if command[1:3] == ("image", "inspect"))
        network_create = next(i for i, command in enumerate(timeline) if command[1:3] == ("network", "create"))
        second_image_inspect = [i for i, command in enumerate(timeline) if command[1:3] == ("image", "inspect")][1]
        docker_run = next(i for i, command in enumerate(timeline) if command[1] == "run")
        self.assertLess(first_image_inspect, network_create)
        self.assertLess(second_image_inspect, docker_run)

    def test_partial_start_persists_image_binding_and_refuses_image_switch(self):
        first = {"id": "sha256:" + "a" * 64, "revision": "b" * 40,
            "version": "0.1.0-rc.1", "platform": "linux/amd64"}
        second = {**first, "id": "sha256:" + "c" * 64}
        info = metadata()
        info.update({"container_id": None, "network_id": None, "lifecycle_state": "initializing"})
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
            root = preview.state_dir("demo")
            path = write_instance(root, info)
            with patch.object(preview, "preflight", return_value={"container": False, "network": False,
                    "volumes": {"postgres": False, "media": False, "state": False}}):
                preview.bind_initial_image(root, info, first)
                self.assertEqual(json.loads(path.read_text())["image_binding"], first)
                with self.assertRaisesRegex(SystemExit, "image binding differs"):
                    preview.bind_initial_image(root, info, second)
            self.assertEqual(json.loads(path.read_text())["image_binding"], first)

    def test_build_start_launches_admitted_immutable_id_even_if_tag_is_retargeted(self):
        image_id = "sha256:" + "a" * 64
        revision = "c" * 40
        tag = f"volt:preview-{revision}"
        info = metadata()
        info.update({"container_id": None, "network_id": None, "lifecycle_state": "initializing",
            "helper_revision": revision, "source_revision": revision, "api_port": 8180, "oidc_port": 8190})
        state = {"network": False, "volumes": set(), "container": False}
        commands = []
        image_row = {"Id": image_id, "Os": "linux", "Architecture": "amd64", "Config": {"Labels": {
            "org.opencontainers.image.revision": revision, "org.opencontainers.image.version": "local-preview"}}}
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
            root = preview.state_dir("demo")
            path = write_instance(root, info)
            def command(*args, capture=False):
                args = tuple(args); commands.append(args)
                if args[:2] == ("git", "rev-parse"): return revision
                if args[:2] == ("git", "status"): return ""
                if args[:2] == ("docker", "build"): return ""
                if args[:3] == ("docker", "network", "create"):
                    state["network"] = True  # a competing client may retarget `tag` here
                    return ""
                if args[:3] == ("docker", "volume", "create"):
                    state["volumes"].add(next(k for k, v in info["volumes"].items() if v == args[-1])); return ""
                if args[:3] == ("docker", "network", "inspect"):
                    return "e" * 64 if args[4] == "{{.Id}}" else "172.19.0.1"
                if args[:2] == ("docker", "run"):
                    state["container"] = True; return "f" * 64
                if args[:3] == ("docker", "inspect", "--format"): return image_id
                raise AssertionError(args)
            def inspect(args, **kwargs):
                args = tuple(args)
                if args[:3] == ("docker", "image", "inspect"):
                    return subprocess.CompletedProcess(args, 0, json.dumps([image_row]), "")
                raise AssertionError(args)
            output = io.StringIO()
            with patch.object(preview, "run", side_effect=command), \
                 patch.object(preview.subprocess, "run", side_effect=inspect), \
                 patch.object(preview, "preflight", return_value={"container": False, "network": False,
                     "volumes": {part: False for part in info["volumes"]}}), \
                 patch.object(preview, "exact_network", side_effect=lambda _: state["network"]), \
                 patch.object(preview, "exact_volume", side_effect=lambda _, part: part in state["volumes"]), \
                 patch.object(preview, "exact_container", side_effect=lambda _: state["container"]), \
                 redirect_stdout(output):
                preview.start(type("Args", (), {"instance": "demo", "image": None, "no_build": False})())
            saved = json.loads(path.read_text())
        launch = next(args for args in commands if args[:2] == ("docker", "run"))
        self.assertEqual(launch[-1], image_id)
        self.assertNotEqual(launch[-1], tag)
        self.assertEqual(saved["image_binding"]["id"], image_id)
        self.assertEqual(saved["image_id"], image_id)
        self.assertEqual(saved["lifecycle_state"], "established")
        self.assertEqual(saved["image_source_revision"], revision)
        self.assertEqual(saved["image_version"], "local-preview")
        self.assertIn(f"image_id={image_id}", output.getvalue())

    def test_default_retry_of_bound_partial_without_saved_mode_fails_closed(self):
        info = metadata()
        info.update({"container_id": None, "network_id": None, "lifecycle_state": "initializing",
            "helper_revision": "c" * 40, "source_revision": "c" * 40,
            "image_binding": {"id": "sha256:" + "a" * 64, "revision": "b" * 40,
                "version": "0.1.0-rc.1", "platform": "linux/amd64"}})
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
            root = preview.state_dir("demo")
            path = write_instance(root, info)
            before = path.read_bytes()
            with patch.object(preview, "preflight", return_value={"container": False, "network": False,
                    "volumes": {part: False for part in info["volumes"]}}), \
                 patch.object(preview, "run", side_effect=lambda *a, capture=False:
                     "c" * 40 if a[:2] == ("git", "rev-parse") else "") as docker_mutation, redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(SystemExit, "without image mode") as result:
                    preview.start(type("Args", (), {"instance": "demo", "image": None, "no_build": False})())
            self.assertIn("explicit no-build image admission options", str(result.exception))
            self.assertEqual([call.args[0] for call in docker_mutation.call_args_list], ["git", "git"])
            self.assertEqual(path.read_bytes(), before)
            result = json.loads(path.read_text())
            self.assertEqual(result["image_binding"]["revision"], "b" * 40)
            self.assertNotIn("image_mode", result)
            self.assertEqual(result["lifecycle_state"], "initializing")

    def test_unbound_partial_resources_are_not_adopted(self):
        info = metadata()
        info.update({"container_id": None, "network_id": None, "lifecycle_state": "initializing"})
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_STATE_HOME": temp}):
            root = preview.state_dir("demo")
            write_instance(root, info)
            with patch.object(preview, "preflight", return_value={"container": False, "network": True,
                    "volumes": {"postgres": True, "media": False, "state": False}}):
                with self.assertRaisesRegex(SystemExit, "without an image binding"):
                    preview.bind_initial_image(root, info, {"id": "sha256:" + "a" * 64,
                        "revision": "b" * 40, "version": "local-preview", "platform": "linux/amd64"})



if __name__ == "__main__":
    unittest.main()
