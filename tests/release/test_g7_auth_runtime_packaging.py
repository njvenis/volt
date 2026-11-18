from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "docker/g7/identity_runtime.sh"
ENTRYPOINT = (ROOT / "docker/g7/entrypoint.sh").read_text()
HEALTHCHECK = (ROOT / "docker/g7/healthcheck.sh").read_text()


class G7AuthRuntimePackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.secrets = self.root / "host-secrets"
        self.runtime_secrets = self.root / "run/uvm-g7-secrets"
        self.state = self.root / "state"
        self.secrets.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.install_log = self.root / "install.jsonl"
        stub = self.bin / "install"
        stub.write_text("""#!/usr/bin/env python3
import json, os, shutil, sys
args = sys.argv[1:]
owner = group = mode = None
directory = False
paths = []
while args:
    arg = args.pop(0)
    if arg == '-d': directory = True
    elif arg == '-o': owner = args.pop(0)
    elif arg == '-g': group = args.pop(0)
    elif arg.startswith('-m'): mode = int(arg[2:] or args.pop(0), 8)
    else: paths.append(arg)
with open(os.environ['INSTALL_LOG'], 'a') as stream:
    stream.write(json.dumps({'owner': owner, 'group': group, 'mode': mode, 'paths': paths})+'\\n')
if directory:
    os.makedirs(paths[-1], exist_ok=True)
    if mode is not None: os.chmod(paths[-1], mode)
else:
    shutil.copyfile(paths[-2], paths[-1])
    if mode is not None: os.chmod(paths[-1], mode)
""")
        stub.chmod(0o755)
        self.env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}",
                    "INSTALL_LOG": str(self.install_log)}

    def tearDown(self):
        self.temp.cleanup()

    def source_script(self, body: str, *args: str, env=None):
        return subprocess.run(["bash", "-c", f'source "$1"; shift; {body}',
                               "bash", str(HELPER), *map(str, args)],
                              env=env or self.env, text=True, capture_output=True)

    def write_secret(self, name: str, data: bytes):
        path = self.secrets / name
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def test_demo_stages_only_scrypt_verifier_as_private_uid_file(self):
        verifier = json.dumps({"schema": "uvm.demo-credential.v1", "username": "demo",
                               "salt": "a" * 32, "password_hash": "b" * 64}).encode()
        self.write_secret("demo-admin-credentials", verifier)
        result = self.source_script(
            'uvm_g7_stage_identity_material "$@"; printf "%s\\n" "$UVM_OIDC_DEMO_CREDENTIALS_FILE"',
            self.secrets, self.runtime_secrets, self.state, "oidc", "demo", "0", "")
        self.assertEqual(result.returncode, 0, result.stderr)
        staged = self.state / "demo-admin-credentials.json"
        self.assertEqual(result.stdout.strip(), str(staged))
        self.assertEqual(staged.read_bytes(), verifier)
        self.assertEqual(staged.stat().st_mode & 0o777, 0o600)
        installs = [json.loads(line) for line in self.install_log.read_text().splitlines()]
        self.assertTrue(any(row["owner"] == "uvm" and row["group"] == "uvm"
                            and row["mode"] == 0o600 for row in installs))

    def test_demo_requires_verifier_and_rejects_okta_material(self):
        missing = self.source_script('uvm_g7_stage_identity_material "$@"',
            self.secrets, self.runtime_secrets, self.state, "oidc", "demo", "0", "")
        self.assertEqual(missing.returncode, 70)
        self.assertIn("G7_IDENTITY_DEMO_CREDENTIAL=missing-or-invalid", missing.stderr)
        self.write_secret("demo-admin-credentials", b'{"schema":"uvm.demo-credential.v1"}\n')
        self.write_secret("okta-publisher.json", b"{}\n")
        mixed = self.source_script('uvm_g7_stage_identity_material "$@"',
            self.secrets, self.runtime_secrets, self.state, "oidc", "demo", "0", "")
        self.assertEqual(mixed.returncode, 70)
        self.assertIn("demo-rejects-external-publisher-material", mixed.stderr)
        self.assertFalse((self.state / "demo-admin-credentials.json").exists())

    def test_external_mode_rejects_demo_verifier_and_partial_okta_pair(self):
        verifier = self.write_secret("demo-admin-credentials", b"{}").read_bytes()
        del verifier
        mixed = self.source_script('uvm_g7_stage_identity_material "$@"',
            self.secrets, self.runtime_secrets, self.state, "oidc", "external", "0", "")
        self.assertEqual(mixed.returncode, 70)
        self.assertIn("external-rejects-demo-credential", mixed.stderr)
        (self.secrets / "demo-admin-credentials").unlink()
        self.write_secret("okta-publisher.json", b"{}\n")
        partial = self.source_script('uvm_g7_stage_identity_material "$@"',
            self.secrets, self.runtime_secrets, self.state, "oidc", "external", "0", "")
        self.assertEqual(partial.returncode, 70)
        self.assertIn("OKTA_MATERIAL=incomplete-or-invalid", partial.stderr)

    def test_external_mode_stages_publisher_read_only_and_never_demo_env(self):
        self.write_secret("okta-publisher.json", b'{"schema_version":1}\n')
        self.write_secret("okta_service_private_key", b"private-key-fixture")
        result = self.source_script(
            'uvm_g7_stage_identity_material "$@"; printf "%s\\n" "${UVM_OIDC_DEMO_CREDENTIALS_FILE-unset}" "$UVM_G7_OKTA_PUBLISHER_CONFIG_FILE"',
            self.secrets, self.runtime_secrets, self.state, "oidc", "external", "0", "")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["unset", str(self.runtime_secrets / "okta-publisher.json")])
        self.assertEqual((self.runtime_secrets / "okta-publisher.json").stat().st_mode & 0o777, 0o440)
        self.assertEqual((self.runtime_secrets / "okta_service_private_key").stat().st_mode & 0o777, 0o400)
        rows = [json.loads(line) for line in self.install_log.read_text().splitlines()]
        self.assertTrue(any(row["owner"] == "uvm" and row["group"] == "uvm" and row["mode"] == 0o400
                            for row in rows))
        self.assertFalse((self.state / "demo-admin-credentials.json").exists())

    def test_recovery_control_skips_local_and_external_auth_secret_staging(self):
        result = self.source_script(
            'uvm_g7_stage_identity_material "$@"; printf "%s\\n" "${UVM_OIDC_DEMO_CREDENTIALS_FILE-unset}" "${UVM_G7_OKTA_PUBLISHER_CONFIG_FILE-unset}"',
            self.secrets, self.runtime_secrets, self.state, "oidc", "demo", "1", "control-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["unset", "unset"])
        self.assertFalse(self.state.exists())

    def test_persistent_local_mode_does_not_stage_synthetic_or_oidc_identity(self):
        self.write_secret("demo-admin-credentials", b"synthetic-only\n")
        self.write_secret("okta-publisher.json", b"{}\n")
        self.write_secret("okta_service_private_key", b"synthetic-key\n")
        result = self.source_script(
            'uvm_g7_stage_identity_material "$@"; printf "%s\\n" "${UVM_OIDC_DEMO_CREDENTIALS_FILE-unset}" "${UVM_G7_OKTA_PUBLISHER_CONFIG_FILE-unset}"',
            self.secrets, self.runtime_secrets, self.state, "local", "local", "0", "")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["unset", "unset"])
        self.assertFalse(self.state.exists())
        self.assertIn("G7_LOCAL_AUTH=config-missing", ENTRYPOINT)
        self.assertIn('UVM_AUTH_MODE:-bearer} == oidc && $UVM_OIDC_DEPLOYMENT_MODE == demo', ENTRYPOINT)
        self.assertIn("G7_LOCAL_AUTH=key-length-invalid", ENTRYPOINT)
        self.assertIn("install -o uvm -g uvm -m 0600 /run/secrets/local-auth.json", ENTRYPOINT)
        self.assertNotIn("chown uvm:uvm /run/volt-bootstrap", ENTRYPOINT)
        self.assertIn("recovery_maintenance prepare-initial-installation", ENTRYPOINT)

    def test_publisher_health_requires_live_child_and_fresh_status(self):
        config = self.root / "publisher.json"
        config.write_text("{}")
        pid_file = self.root / "pid"
        fake_python = self.bin / "python-status"
        invocation = self.root / "python-invocation.json"
        fake_python.write_text(f"#!/usr/bin/env python3\nimport json,os,sys\nopen({str(invocation)!r},'w').write(json.dumps(sys.argv[1:]))\nraise SystemExit(int(os.environ.get('STATUS','0')))\n")
        fake_python.chmod(0o755)
        pid_file.write_text("99999999\n")
        dead = self.source_script('uvm_g7_okta_publisher_healthy "$@"', config, pid_file, fake_python)
        self.assertNotEqual(dead.returncode, 0)
        pid_file.write_text(f"{os.getpid()}\n")
        fresh = self.source_script('uvm_g7_okta_publisher_healthy "$@"', config, pid_file, fake_python,
                                   env={**self.env, "STATUS": "0"})
        self.assertEqual(fresh.returncode, 0, fresh.stderr)
        self.assertEqual(json.loads(invocation.read_text()), ["-m", "uvm.auth.okta_publisher",
                                                               "--config", str(config), "--status"])
        stale_python = self.bin / "python-stale"
        stale_python.write_text("#!/bin/sh\nexit 1\n")
        stale_python.chmod(0o755)
        stale = self.source_script('uvm_g7_okta_publisher_healthy "$@"', config, pid_file, stale_python)
        self.assertNotEqual(stale.returncode, 0)
        absent = self.source_script('uvm_g7_okta_publisher_healthy "$@"', self.root / "absent",
                                    self.root / "missing-pid", stale_python)
        self.assertEqual(absent.returncode, 0)

    def test_each_publisher_launch_invalidates_only_transient_readiness(self):
        publisher_state = self.state / "oidc-publisher"
        publisher_state.mkdir(parents=True)
        status_file = publisher_state / "status.json"
        revision_file = publisher_state / "revision.json"
        status_file.write_text(json.dumps({"last_success_epoch": time.time(),
                                           "last_error_class": None}) + "\n")
        revision_file.write_text('{"revision":41}\n')
        config = self.root / "publisher.json"
        config.write_text("{}")
        pid_file = self.root / "pid"
        pid_file.write_text(f"{os.getpid()}\n")
        status_probe = self.bin / "python-held-status"
        status_probe.write_text(
            f"#!/usr/bin/env python3\nfrom pathlib import Path\nimport sys\n"
            f"raise SystemExit(0 if Path({str(status_file)!r}).is_file() else 1)\n")
        status_probe.chmod(0o755)
        prior = self.source_script('uvm_g7_okta_publisher_healthy "$@"',
                                   config, pid_file, status_probe)
        self.assertEqual(prior.returncode, 0,
                         msg="retained recent status would admit a restart before invalidation")
        invalidate = self.source_script('uvm_g7_invalidate_publisher_readiness "$@"', publisher_state)
        self.assertEqual(invalidate.returncode, 0, invalidate.stderr)
        self.assertFalse(status_file.exists())
        self.assertEqual(json.loads(revision_file.read_text()), {"revision": 41})

        held = self.source_script('uvm_g7_okta_publisher_healthy "$@"',
                                  config, pid_file, status_probe)
        self.assertNotEqual(held.returncode, 0, "old heartbeat must not admit this launch")

        status_file.write_text('{"last_success_epoch":1000000000,"last_error_class":null}\n')
        successful = self.source_script('uvm_g7_okta_publisher_healthy "$@"',
                                        config, pid_file, status_probe)
        self.assertEqual(successful.returncode, 0, successful.stderr)
        self.assertEqual(json.loads(revision_file.read_text()), {"revision": 41})

    def test_supervisor_orders_publisher_readiness_and_stops_it_as_a_writer(self):
        sync_ready = ENTRYPOINT.index("wait_for 'loopback OIDC sync adapter'")
        publisher_start = ENTRYPOINT.index("start_child okta-identity-publisher")
        invalidation = ENTRYPOINT.index("uvm_g7_invalidate_publisher_readiness /opt/uvm/state/oidc-publisher")
        first_snapshot = ENTRYPOINT.index("Okta publisher first successful full snapshot")
        readiness = ENTRYPOINT.index("echo 'G7_READINESS=ready'")
        self.assertLess(sync_ready, publisher_start)
        self.assertLess(invalidation, publisher_start)
        self.assertLess(publisher_start, first_snapshot)
        self.assertLess(first_snapshot, readiness)
        self.assertIn("stop_phase writers okta-identity-publisher", ENTRYPOINT)
        self.assertIn("stop_phase quiesce-producers okta-identity-publisher", ENTRYPOINT)
        self.assertIn("uvm_g7_okta_publisher_healthy", HEALTHCHECK)
        self.assertIn("UVM_OIDC_SYNC_SECRET_FILE=/run/uvm-g7-secrets/oidc_sync_secret", ENTRYPOINT)


if __name__ == "__main__":
    unittest.main()
