from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from uvm.installer.recovery_authority import PATH_POLICY, PROFILE, _canonical, approve_document
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[2]
# Unit subprocesses use the current test group; real gid1800/uid1800 access is
# qualified separately through Docker with the unmodified production constant.
HELPER = [sys.executable, "-c", "import os; import uvm.installer.recovery_authority as h; h.RUNTIME_GID=os.getgid(); h.main()"]


class RecoveryAuthorityPreparationTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[dict, str]:
        root.chmod(0o700)
        (root / "secrets").mkdir(mode=0o700)
        installation_id, journal_id = str(uuid.uuid4()), str(uuid.uuid4())
        secret_source_id = str(uuid.uuid4())
        local_config = {
            "schema_version": 1, "installation_id": installation_id,
            "secret_source": {"kind": "encrypted_local_v1", "secret_source_id": secret_source_id,
                              "key_path": "/run/uvm-connector/local-key"},
        }
        (root / "local-auth.json").write_text(json.dumps(local_config))
        (root / "local-auth.json").chmod(0o600)
        (root / '.env').write_text("VOLT_LOCAL_START_RESOURCES_SHA256='old-resource-hash'\n")
        (root / '.env').chmod(0o600)
        import hashlib
        (root / "instance.json").write_text(json.dumps({
            "format_version": 1, "mode": "local", "installation_id": installation_id,
            "local_recovery_journal_id": journal_id, "established": False,
            "env_sha256": hashlib.sha256((root / '.env').read_bytes()).hexdigest(),
            "local_auth_config_sha256": hashlib.sha256((root / "local-auth.json").read_bytes()).hexdigest(),
        }))
        (root / "instance.json").chmod(0o600)
        (root / "secrets/local-auth-key").write_bytes(b"a" * 32)
        (root / "secrets/local-auth-key").chmod(0o600)
        request = {"schema_version": 1, "profile": PROFILE,
                   "installation_id": installation_id, "journal_id": journal_id,
                   "path_policy": PATH_POLICY}
        return request, journal_id

    def arm_start(self, root: Path, journal: dict, *, initial=False):
        journal["image_admission"] = {"id": "sha256:" + "d" * 64}
        resources = {"unit_fixture": "owned-resource-inspection"}
        record = {**journal["local_recovery_custody"], "document_type": "local_start_admission_v2",
            "local_auth_config_sha256": journal["local_auth_config_sha256"],
            "image_id": journal["image_admission"]["id"],
            "resources_sha256": hashlib.sha256(_canonical(resources)).hexdigest(),
            "initial_preparation": initial}
        journal.update(local_start_resources=resources, local_start_admission=record,
                       local_start_admission_sha256=hashlib.sha256(_canonical(record)).hexdigest())
        path = root / "secrets/local-start-admission/admission.json"
        path.write_bytes(_canonical(record)); path.chmod(0o600)
        return record

    def invoke(self, root: Path, request: dict) -> subprocess.CompletedProcess:
        return subprocess.run([*HELPER,
                               "prepare", "--request-stdin", "--instance-root", str(root)],
                              input=json.dumps(request), text=True, capture_output=True,
                              cwd=ROOT, check=False)

    def test_prepare_is_create_once_closed_and_response_contains_no_private_material(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request, journal_id = self.fixture(root)
            first = self.invoke(root, request)
            self.assertEqual(first.returncode, 0, first.stderr)
            response = json.loads(first.stdout)
            self.assertEqual(response["journal_id"], journal_id)
            self.assertEqual(response["status"], "prepared")
            self.assertNotIn("key", " ".join(response.keys()).replace("key_id", ""))
            self.assertEqual(set(response), {"schema_version", "profile", "status",
                "installation_id", "journal_id", "issuer_key_id", "operator_key_id",
                "issuer_public_sha256", "operator_public_sha256", "restore_generation",
                "recovery_epoch_id"})
            for relative in ("local-recovery.json", "secrets/local-recovery-runtime/issuer.key",
                    "secrets/local-recovery-runtime/issuer.pub", "secrets/local-recovery-runtime/operator.pub",
                    "secrets/local-recovery-runtime/material.key", "secrets/local-recovery-authority/operator.key",
                    "secrets/local-recovery-authority/host.json", "secrets/local-restore-fence/fence.json"):
                path = root / relative
                self.assertEqual(path.stat().st_mode & 0o777,
                                 0o640 if relative.endswith("fence.json") else 0o600)
            resumed = self.invoke(root, request)
            self.assertEqual(resumed.returncode, 0, resumed.stderr)
            self.assertEqual(json.loads(resumed.stdout), response)
            (root / "secrets/local-recovery-runtime/material.key").unlink()
            missing = self.invoke(root, request)
            self.assertNotEqual(missing.returncode, 0)
            self.assertFalse((root / "secrets/local-recovery-runtime/material.key").exists())

    def test_changed_material_and_coherent_signing_replacement_fail_host_inventory(self):
        for coherent in (False, True):
            with self.subTest(coherent=coherent), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                request, _ = self.fixture(root)
                result = self.invoke(root, request)
                self.assertEqual(result.returncode, 0, result.stderr)
                if coherent:
                    key = Ed25519PrivateKey.generate()
                    (root / "secrets/local-recovery-runtime/issuer.key").write_bytes(key.private_bytes_raw())
                    for relative in ("secrets/local-recovery-runtime/issuer.pub", "secrets/local-recovery-authority/issuer.pub"):
                        (root / relative).write_bytes(key.public_key().public_bytes_raw())
                else:
                    (root / "secrets/local-recovery-runtime/material.key").write_bytes(b"z" * 32)
                self.assertNotEqual(self.invoke(root, request).returncode, 0)

    def test_restore_writer_recovers_durable_intent_after_each_projection_crash(self):
        from uvm.installer import recovery_authority as helper
        for crash in ('before-fence', 'after-fence', 'orphan-file', 'orphan-symlink', 'orphan-fifo'):
            with self.subTest(crash=crash), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                request, _ = self.fixture(root)
                self.assertEqual(self.invoke(root, request).returncode, 0)
                journal = json.loads((root / 'instance.json').read_text())
                self.arm_start(root, journal)
                journal['backup_inventory'] = {'postgres': {'postgres_version': '18'}, 'media': {}, 'state': {}}
                (root / 'instance.json').write_text(json.dumps(journal))
                before = journal['local_recovery_custody']
                original_publish = helper._publish_fence
                def interrupted_publish(*args):
                    # The intended epoch must already be durable before either
                    # the old admission is removed or the new fence is visible.
                    pending = json.loads((root / 'instance.json').read_text())
                    self.assertEqual(pending['restore_fence_transition']['from'], before)
                    self.assertTrue(pending['restore_pending'])
                    self.assertEqual(hashlib.sha256((root / '.env').read_bytes()).hexdigest(),
                                     pending['local_start_environment_pending_sha256'])
                    if crash == 'after-fence':
                        original_publish(*args)
                    raise OSError('simulated writer crash')
                with patch.object(helper, 'RUNTIME_GID', os.getgid()), patch.object(helper, '_publish_fence', interrupted_publish):
                    with self.assertRaises(OSError):
                        helper.advance_fence(SimpleNamespace(instance_root=str(root)))
                pending = json.loads((root / 'instance.json').read_text())
                target = pending['restore_fence_transition']['to']
                self.assertEqual(target['restore_generation'], 1)
                orphan = root / 'secrets/local-restore-fence/.fence.0123456789abcdef'
                if crash == 'orphan-file':
                    orphan.write_bytes(b'interrupted partial write'); orphan.chmod(0o600)
                elif crash in {'orphan-symlink', 'orphan-fifo'}:
                    if crash == 'orphan-symlink':
                        orphan.symlink_to('/dev/null')
                    else:
                        os.mkfifo(orphan, 0o600)
                    with patch.object(helper, 'RUNTIME_GID', os.getgid()), self.assertRaises(ValueError):
                        helper.advance_fence(SimpleNamespace(instance_root=str(root)))
                    self.assertEqual(json.loads((root / 'instance.json').read_text()), pending)
                    orphan.unlink()
                self.assertNotEqual(self.invoke(root, request).returncode, 0)
                with patch.object(helper, 'RUNTIME_GID', os.getgid()):
                    helper.advance_fence(SimpleNamespace(instance_root=str(root)))
                repaired = json.loads((root / 'instance.json').read_text())
                self.assertEqual(repaired['local_recovery_custody'], target)
                self.assertNotIn('restore_fence_transition', repaired)
                self.assertNotIn('local_start_environment_pending_sha256', repaired)
                self.assertEqual((root / '.env').read_text(), "VOLT_LOCAL_START_RESOURCES_SHA256=''\n")
                self.assertEqual(repaired['env_sha256'], hashlib.sha256((root / '.env').read_bytes()).hexdigest())
                self.assertTrue(repaired['restore_pending'])
                self.assertNotIn('local_start_admission', repaired)
                self.assertFalse(orphan.exists())
                self.assertFalse((root / 'secrets/local-start-admission/admission.json').exists())
                self.assertEqual(json.loads((root / 'secrets/local-restore-fence/fence.json').read_text()), target)
                self.assertEqual(self.invoke(root, request).returncode, 0)

    def test_restore_resume_and_acknowledgement_require_the_exact_current_tuple(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request, _ = self.fixture(root)
            self.assertEqual(self.invoke(root, request).returncode, 0)
            journal_path = root / "instance.json"
            journal = json.loads(journal_path.read_text())
            custody = {**journal["local_recovery_custody"], "restore_generation": 2,
                       "recovery_epoch_id": str(uuid.uuid4())}
            journal.update(local_recovery_custody=custody, restore_pending=True, restore_imported=True)
            self.arm_start(root, journal)
            journal_path.write_text(json.dumps(journal))
            (root / "secrets/local-restore-fence/fence.json").write_text(json.dumps(custody))
            resumed = self.invoke(root, request)
            self.assertEqual(resumed.returncode, 0, resumed.stderr)
            self.assertEqual(json.loads(resumed.stdout)["restore_generation"], 2)
            self.assertEqual(json.loads(resumed.stdout)["recovery_epoch_id"], custody["recovery_epoch_id"])
            acknowledgement = {**custody, "operation": "apply-local-restore-fence", "status": "applied",
                "revoked_sessions": 1, "revoked_capabilities": 1, "quarantined_connectors": 1}
            command = [*HELPER, "acknowledge", "--request-stdin", "--instance-root", str(root)]
            bad = subprocess.run(command, input=json.dumps({**acknowledgement, "restore_generation": 1}),
                                 text=True, capture_output=True, cwd=ROOT)
            self.assertNotEqual(bad.returncode, 0)
            self.assertTrue(json.loads(journal_path.read_text())["restore_pending"])
            valid = subprocess.run(command, input=json.dumps(acknowledgement), text=True, capture_output=True, cwd=ROOT)
            self.assertEqual(valid.returncode, 0, valid.stderr)
            committed = json.loads(journal_path.read_text())
            self.assertFalse(committed["restore_pending"])
            self.assertTrue(committed["restore_sessions_revoked"])
            self.assertTrue(committed["restore_capabilities_revoked"])
            self.assertEqual(committed["local_recovery_acknowledgement"], acknowledgement)

    def test_fifo_custody_input_is_rejected_without_blocking(self):
        for relative in ("secrets/local-restore-fence/fence.json", "secrets/local-recovery-runtime/material.key"):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                request, _ = self.fixture(root)
                self.assertEqual(self.invoke(root, request).returncode, 0)
                target = root / relative
                target.unlink()
                os.mkfifo(target, 0o600)
                if relative.endswith("fence.json"):
                    target.chmod(0o640)
                result = subprocess.run([*HELPER, "validate", "--request-stdin", "--instance-root", str(root)],
                    input=json.dumps(request), text=True, capture_output=True, cwd=ROOT, timeout=3)
                self.assertNotEqual(result.returncode, 0)

    def test_established_resume_requires_an_exact_current_acknowledgement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request, _ = self.fixture(root)
            self.assertEqual(self.invoke(root, request).returncode, 0)
            journal_path = root / "instance.json"
            journal = json.loads(journal_path.read_text())
            journal["established"] = True
            self.arm_start(root, journal)
            command = [*HELPER, "validate", "--request-stdin", "--instance-root", str(root)]
            def check():
                journal_path.write_text(json.dumps(journal))
                return subprocess.run(command, input=json.dumps(request), text=True, capture_output=True, cwd=ROOT, timeout=3)
            self.assertNotEqual(check().returncode, 0)
            journal["local_recovery_acknowledgement"] = {**journal["local_recovery_custody"],
                "operation": "apply-local-restore-fence", "status": "already_applied",
                "revoked_sessions": 0, "revoked_capabilities": 0, "quarantined_connectors": 0}
            accepted = check()
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            journal["local_recovery_acknowledgement"]["journal_id"] = str(uuid.uuid4())
            self.assertNotEqual(check().returncode, 0)

    def test_wrong_path_policy_fails_before_creating_any_custody_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request, _ = self.fixture(root)
            request["path_policy"] = {**PATH_POLICY, "authority_directory": "secrets/wider"}
            result = self.invoke(root, request)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual({path.name for path in root.iterdir()},
                             {"instance.json", "local-auth.json", "secrets", ".env"})
            self.assertEqual({path.name for path in (root / "secrets").iterdir()}, {"local-auth-key"})

    def test_established_installation_and_changed_journal_cannot_create_or_rebind_custody(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request, _ = self.fixture(root)
            journal = json.loads((root / "instance.json").read_text())
            journal["established"] = True
            (root / "instance.json").write_text(json.dumps(journal))
            (root / "instance.json").chmod(0o600)
            result = self.invoke(root, request)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual({path.name for path in (root / "secrets").iterdir()}, {"local-auth-key"})

    def test_request_and_resume_validate_fixed_journal_without_key_regeneration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request, journal_id = self.fixture(root)
            prepared = self.invoke(root, request)
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            process = subprocess.run([*HELPER,
                "request", "--instance-root", str(root)],
                text=True, capture_output=True, cwd=ROOT, check=False)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(json.loads(process.stdout), request)
            before = {str(path.relative_to(root)): path.read_bytes()
                      for path in root.rglob("*") if path.is_file()}
            validation = subprocess.run([*HELPER,
                "validate", "--request-stdin", "--instance-root", str(root)],
                input=json.dumps(request), text=True, capture_output=True, cwd=ROOT, check=False)
            self.assertEqual(validation.returncode, 0, validation.stderr)
            self.assertEqual(json.loads(validation.stdout)["journal_id"], journal_id)
            after = {str(path.relative_to(root)): path.read_bytes()
                     for path in root.rglob("*") if path.is_file()}
            self.assertEqual(after, before)

    def test_host_approval_binds_signed_attestation_to_independent_fence_and_target(self):
        installation_id, journal_id, epoch_id = (str(uuid.uuid4()) for _ in range(3))
        connector_id, source_id, secret_id, version_id = (str(uuid.uuid4()) for _ in range(4))
        operator_key_id, issuer_key_id = str(uuid.uuid4()), str(uuid.uuid4())
        operator = Ed25519PrivateKey.generate()
        issuer = Ed25519PrivateKey.generate()
        raw = lambda key: key.private_bytes_raw()
        public = lambda key: key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        source_tuple = {"source_family": "qualys", "source_account_id": "account-1", "scope_key": "vm"}
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        attestation = {"schema_version": 2, "profile": PROFILE, "document_type": "credential_attestation",
            "attestation_id": str(uuid.uuid4()), "installation_id": installation_id,
            "issuer_key_id": issuer_key_id, "connector_id": connector_id, "source_id": source_id,
            "source_tuple": source_tuple, "secret_id": secret_id, "version_id": version_id,
            "purpose": "qualys_vm_basic", "recovery_epoch_id": epoch_id, "issued_at": now,
            "issued_after_epoch": True, "freshness_policy": "no_retained_password_reuse_v1",
            "credential_commitment": "a" * 64}
        attestation["signature"] = base64.b64encode(issuer.sign(_canonical(attestation))).decode("ascii")
        target = {"connector_id": connector_id, "source_id": source_id, "source_tuple": source_tuple,
            "secret_id": secret_id, "version_id": version_id, "purpose": "qualys_vm_basic",
            "configuration_revision": 7, "display_name": "Qualys Production", "account_label": "prod"}
        request = {"schema_version": 1, "profile": PROFILE,
            "operation": "scanner_recovery_approval_request", "installation_id": installation_id,
            "operator_key_id": operator_key_id, "operator_id": f"local-host:{installation_id}",
            "journal_id": journal_id, "restore_generation": 1, "recovery_epoch_id": epoch_id,
            "target": target, "attestation": attestation,
            "attestation_sha256": hashlib.sha256(_canonical(attestation)).hexdigest(),
            "rationale": "Replace restored scanner credential", "evidence_ref": "recovery-case-7"}
        host = {"schema_version": 1, "profile": PROFILE, "installation_id": installation_id,
            "operator_id": f"local-host:{installation_id}", "operator_key_id": operator_key_id,
            "operator_private_key_file": "/authority/operator.key",
            "operator_public_key_file": "/authority/operator.pub", "issuer_key_id": issuer_key_id,
            "issuer_public_key_file": "/authority/issuer.pub",
            "restore_fence_file": "/authority/fence/fence.json",
            "journal_file": "/authority/instance.json"}
        custody = {"schema_version": 1, "profile": PROFILE, "installation_id": installation_id,
            "journal_id": journal_id, "restore_generation": 1, "recovery_epoch_id": epoch_id}
        journal = {"mode": "local", "installation_id": installation_id,
            "local_recovery_journal_id": journal_id, "local_recovery_custody": custody}
        document = approve_document(request, host, raw(operator), public(operator), public(issuer), custody, journal)
        self.assertEqual(document["attestation_sha256"], request["attestation_sha256"])
        signature = base64.b64decode(document.pop("signature"), validate=True)
        Ed25519PublicKey.from_public_bytes(public(operator)).verify(signature, _canonical(document))
        issued = datetime.fromisoformat(document["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(document["expires_at"].replace("Z", "+00:00"))
        self.assertEqual(expires - issued, timedelta(minutes=15))
        with self.assertRaisesRegex(ValueError, "host restore fence"):
            approve_document(request, host, raw(operator), public(operator), public(issuer),
                {**custody, "restore_generation": 2}, journal)

    def test_source_selector_requires_one_exact_human_label_and_keeps_ids_in_machine_output(self):
        installation, connector, source = (str(uuid.uuid4()) for _ in range(3))
        targets = {"schema_version": 1, "profile": PROFILE, "installation_id": installation,
            "targets": [{"connector_id": connector, "source_id": source,
                "display_name": "Qualys Prod", "account_label": "account-1", "platform_id": "platform-1",
                "state": "quarantined", "configuration_revision": 4}]}
        command = [*HELPER, "select-target",
            "--request-stdin", "--source", "Qualys Prod [account-1]", "--rationale", "Fresh scanner credential",
            "--evidence-ref", "recovery-case-9"]
        targets["targets"].append({**targets["targets"][0], "display_name": "Unconfigured",
                                    "configuration_revision": 0})
        result = subprocess.run(command, input=json.dumps(targets), text=True, capture_output=True,
                                cwd=ROOT, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        request = json.loads(result.stdout)
        self.assertEqual(request["connector_id"], connector)
        self.assertEqual(request["source_id"], source)
        self.assertNotIn("display_name", request)
        command[command.index("Qualys Prod [account-1]")] = "Qualys Prod"
        refused = subprocess.run(command, input=json.dumps(targets), text=True, capture_output=True,
                                 cwd=ROOT, check=False)
        self.assertNotEqual(refused.returncode, 0)


if __name__ == "__main__":
    unittest.main()
