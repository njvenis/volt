from __future__ import annotations

import unittest
import base64
from datetime import datetime, timezone
import hashlib
import json
import tempfile
import tarfile
from pathlib import Path
import uuid
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from uvm.operations.observer_settings import (
    BACKUP_FIELDS, ObserverSettingsError, validate_backup_values,
)
from uvm.operations.backup_host import canonical_json, digest, validate_policy, verify_signature
from uvm.operations.startup_fence import verify_startup_fence
from uvm.operations.api import _discovery_cursor, _read_discovery_cursor
from tools.g7_backup_recovery import RecoveryError, restore_new_volumes, verify_archive
from tools.g7_backup_controller import Controller, _last_intent_revision
from tools.g7_upgrade_assertions import validate_verification_queue, validate_epoch_two_readbacks, classify_verification_queue
from tools.g7_product_inventory import compare as compare_product_inventory
from uvm.api.recovery_readonly import (recovery_control_request_decision,
    recovery_request_decision as uvm_recovery_request_decision)
from docker.g7.verification_middleware import recovery_request_decision


class BackupSettingsValidationTests(unittest.TestCase):
    def setUp(self):
        self.policy = {
            "bounds": {
                "interval_seconds": {"min": 60, "max": 3600},
                "timeout_seconds": {"min": 1, "max": 1800},
                "maximum_backup_age_seconds": {"min": 60, "max": 86400},
                "restore_verification_timeout_seconds": {"min": 1, "max": 3600},
            },
            "archive_target_refs": ["archive-a"],
            "recovery_profile_refs": ["profile-a"],
        }
        self.values = {
            "interval_seconds": 300,
            "timeout_seconds": 120,
            "maximum_backup_age_seconds": 7200,
            "restore_verification_timeout_seconds": 600,
            "archive_target_ref": "archive-a",
            "recovery_profile_ref": "profile-a",
        }

    def test_complete_host_bounded_values_are_preserved(self):
        self.assertEqual(set(validate_backup_values(self.values, self.policy)), set(BACKUP_FIELDS))

    def test_initial_controller_journal_accepts_nullable_last_intent(self):
        self.assertEqual(_last_intent_revision({"last_intent": None}), 0)
        self.assertEqual(_last_intent_revision({"last_intent": {"revision": 4}}), 4)
        with self.assertRaises(RecoveryError):
            _last_intent_revision({"last_intent": {"revision": True}})

    def test_startup_fence_binds_exact_restore_target_and_connector_uuid(self):
        private = Ed25519PrivateKey.generate()
        volume_ids = {"postgres_cluster": "pg-new", "ce_media": "media-new",
            "uvm_state": "uvm-new"}
        document = {"schema_version": 1, "deployment_id": "g7-local",
            "target_image_digest": "sha256:" + "a" * 64, "volume_ids": volume_ids,
            "archive_digest": "sha256:" + "b" * 64, "recovery_epoch": 3,
            "connector_recovery_id": str(uuid.uuid4()),
            "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        sig = private.sign(canonical_json(document))
        signed = {**document, "signature": {"algorithm": "Ed25519", "key_id": "test-key",
            "value": base64.urlsafe_b64encode(sig).decode().rstrip("=")}}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key = root / "pub.pem"
            key.write_bytes(private.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            token = root / "token.json"
            token.write_bytes(canonical_json(signed))
            verified = verify_startup_fence(str(token), str(key), deployment_id="g7-local",
                image_digest=document["target_image_digest"], volume_ids=volume_ids,
                archive_digest=document["archive_digest"], recovery_epoch=3,
                connector_recovery_id=document["connector_recovery_id"], key_id="test-key")
            self.assertEqual(verified["recovery_epoch"], 3)
            with self.assertRaises(ValueError):
                verify_startup_fence(str(token), str(key), deployment_id="g7-local",
                    image_digest=document["target_image_digest"], volume_ids={**volume_ids,
                        "uvm_state": "wrong-volume"}, archive_digest=document["archive_digest"],
                    recovery_epoch=3, connector_recovery_id=document["connector_recovery_id"],
                    key_id="test-key")

    def test_upgrade_compatibility_admission_binds_schema_and_image_package_pair(self):
        private = Ed25519PrivateKey.generate()
        volume_ids = {"postgres_cluster": "pg-upgrade", "ce_media": "media-upgrade",
            "uvm_state": "uvm-upgrade"}
        image_digest = "sha256:" + "a" * 64
        archive_digest = "sha256:" + "b" * 64
        package_digest = "sha256:" + hashlib.sha256(
            b"pyproject.toml\0pyproject\n\0uv.lock\0uv lock\n\0").hexdigest()
        admission = {"admission_id": str(uuid.uuid4()), "recovery_epoch": 4,
            "source_image_digest": "sha256:" + "d" * 64,
            "source_package_manifest_digest": "sha256:" + "e" * 64,
            "target_image_digest": image_digest,
            "target_package_manifest_digest": package_digest,
            "archive_digest": archive_digest, "from_schema": "0058", "to_schema": "0059",
            "volume_ids": volume_ids}
        document = {"schema_version": 1, "deployment_id": "g7-local",
            "target_image_digest": image_digest, "volume_ids": volume_ids,
            "archive_digest": archive_digest, "recovery_epoch": 4,
            "connector_recovery_id": str(uuid.uuid4()),
            "compatibility_admission": admission,
            "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        signed = {**document, "signature": {"algorithm": "Ed25519", "key_id": "test-key",
            "value": base64.urlsafe_b64encode(private.sign(canonical_json(document))).decode().rstrip("=")}}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key = root / "pub.pem"
            key.write_bytes(private.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            token = root / "token.json"
            token.write_bytes(canonical_json(signed))
            with patch("uvm.operations.startup_fence._runtime_package_digest", return_value=package_digest), \
                    patch.dict("os.environ", {"UVM_G7_SCHEMA_MODE": "upgrade-verification"}):
                verified = verify_startup_fence(str(token), str(key), deployment_id="g7-local",
                    image_digest=image_digest, volume_ids=volume_ids, archive_digest=archive_digest,
                    recovery_epoch=4, connector_recovery_id=document["connector_recovery_id"],
                    key_id="test-key")
            self.assertEqual(verified["compatibility_admission"]["from_schema"], "0058")

    def test_schema_compatibility_admission_is_journaled_before_replay(self):
        with tempfile.TemporaryDirectory() as temp:
            controller = Controller.__new__(Controller)
            controller.deployment = "g7-local"
            controller.journal = Path(temp) / "controller-journal.json"
            controller.state = {"schema_version": 1, "deployment_id": "g7-local",
                "recovery_epoch_floor": 1, "schema_compatibility_admissions": {}}
            admission = {"admission_id": str(uuid.uuid4()), "recovery_epoch": 1,
                "source_image_digest": "sha256:" + "a" * 64,
                "source_package_manifest_digest": "sha256:" + "b" * 64,
                "target_image_digest": "sha256:" + "c" * 64,
                "target_package_manifest_digest": "sha256:" + "d" * 64,
                "archive_digest": "sha256:" + "e" * 64,
                "from_schema": "0058", "to_schema": "0059",
                "volume_ids": {"postgres_cluster": "pg", "ce_media": "media", "uvm_state": "uvm"}}
            saved = controller.journal_schema_compatibility_admission(admission)
            retained = json.loads(controller.journal.read_text())
            self.assertEqual(retained["schema_compatibility_admissions"]["1"], admission)
            replay = {**admission, "admission_id": str(uuid.uuid4())}
            self.assertEqual(controller.journal_schema_compatibility_admission(replay), admission)
            conflicting = {**replay, "target_image_digest": "sha256:" + "f" * 64}
            with self.assertRaises(RecoveryError):
                controller.journal_schema_compatibility_admission(conflicting)
            self.assertEqual(saved, admission)

    def test_development_rollback_request_requires_journal_bound_measured_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            controller = Controller.__new__(Controller)
            controller.deployment = "g7-local"
            controller.journal = Path(temp) / "controller-journal.json"
            controller.state = {"schema_version": 1, "deployment_id": "g7-local",
                "recovery_epoch_floor": 1}
            request = {"request_id": str(uuid.uuid4()), "state": "development_rollback_requested",
                "recovery_epoch": 1, "archive_id": str(uuid.uuid4()),
                "archive_digest": "sha256:" + "a" * 64,
                "source_image_digest": "sha256:" + "b" * 64,
                "source_package_manifest_digest": "sha256:" + "c" * 64,
                "upgraded_image_digest": "sha256:" + "d" * 64,
                "target_package_manifest_digest": "sha256:" + "e" * 64,
                "forward_volume_ids": {"postgres_cluster": "pg", "ce_media": "media", "uvm_state": "uvm"},
                "schema_head": "0059", "inventory_attestation_id": str(uuid.uuid4()),
                "inventory_attestation_digest": "sha256:" + "f" * 64, "product_write_count": 0,
                "control_mutation_count": 4,
                "unexpected_inventory_change_count": 0, "unresolved_external_effect_count": 0,
                "ingress_fenced": True, "egress_fenced": True, "public_readback_match": True,
                "requested_at": "2026-10-28T12:00:00Z"}
            attestation={"attestation_id":request["inventory_attestation_id"],"recovery_epoch":1,
                "forward_volume_ids":request["forward_volume_ids"],"source_digest":"sha256:"+"1"*64,
                "candidate_digest":"sha256:"+"2"*64,"delta_digest":"sha256:"+"3"*64,
                "archive_digest":request["archive_digest"],"source_image_digest":request["source_image_digest"],
                "source_package_manifest_digest":request["source_package_manifest_digest"],
                "upgraded_image_digest":request["upgraded_image_digest"],
                "target_package_manifest_digest":request["target_package_manifest_digest"],
                "product_mutation_count":0,"control_mutation_count":4,
                "unexpected_inventory_change_count":0,
                "unresolved_external_effect_count":0,"controller_journal_pre_digest":"sha256:"+"4"*64}
            attestation["attestation_digest"]="sha256:"+hashlib.sha256(json.dumps(attestation,sort_keys=True,separators=(",",":")).encode()).hexdigest()
            controller.state["product_inventory_attestations"]={attestation["attestation_id"]:attestation}
            request["inventory_attestation_digest"]=attestation["attestation_digest"]
            with self.assertRaises(RecoveryError):
                controller.journal_development_rollback_request({**request,"unresolved_external_effect_count":1})

            self.assertEqual(controller.journal_development_rollback_request(request), request)
            retained = json.loads(controller.journal.read_text())
            self.assertEqual(retained["development_rollback_requests"]["1"], request)
            with self.assertRaises(RecoveryError):
                controller.journal_development_rollback_request({**request,
                    "product_write_count": 1, "request_id": str(uuid.uuid4())})

    def test_full_inventory_detects_same_count_payload_and_unrelated_table_changes(self):
        before={"uvm":{"product":{"columns":[],"schema_sha256":"a","rows":[{"key":[1],"payload_sha256":"old"}],"row_count":1}},"ce":{"findings":{"columns":[],"schema_sha256":"b","rows":[],"row_count":0}},"media":[]}
        payload={"uvm":{"product":{"columns":[],"schema_sha256":"a","rows":[{"key":[1],"payload_sha256":"new"}],"row_count":1}},"ce":before["ce"],"media":[]}
        unrelated={"uvm":{"product":before["uvm"]["product"],"new_unrelated":{"columns":[],"schema_sha256":"c","rows":[],"row_count":0}},"ce":before["ce"],"media":[]}
        self.assertEqual(compare_product_inventory(before,payload)["unexpected_inventory_change_count"],1)
        self.assertEqual(compare_product_inventory(before,unrelated)["unexpected_inventory_change_count"],1)

    def test_inventory_rejects_unjournaled_control_payload_revision_and_schema(self):
        import copy
        def table(payload):
            from tools.g7_product_inventory import digest
            return {"columns":[],"schema_sha256":"schema","rows":[{"key":["g7-local"],"payload_sha256":digest(payload)}],"row_count":1}
        before={"uvm":{"g7_backup_state":table({"effective_revision":4}),"g7_backup_settings_revisions":table({"revision":4})},"ce":{},"media":[]}
        expected=copy.deepcopy(before)
        for name,field,value in (("g7_backup_state","rows",[{"key":["g7-local"],"payload_sha256":"arbitrary"}]),("g7_backup_settings_revisions","rows",before['uvm']['g7_backup_settings_revisions']['rows']+[{"key":["extra"],"payload_sha256":"extra"}]),("g7_backup_state","schema_sha256","unexpected")):
            after=copy.deepcopy(expected); after['uvm'][name][field]=value
            self.assertGreater(compare_product_inventory(before,after,expected)['unexpected_inventory_change_count'],0)

    def test_verification_queue_validator_rejects_unknown_tasks_unresolved_and_failed_broker(self):
        intent={"unresolved_count":0,"missing_expected_tables":[]}
        obs=[{"name":n,"worker_ids":[],"exit_code":69,"expected_absent_worker_response":True,"stdout_bytes":0,"stderr_sha256":hashlib.sha256(b"Error: No nodes replied within time constraint\n").hexdigest(),"classification":"workers_absent"} for n in ("celery_active","celery_reserved","celery_scheduled")]
        obs.append({"name":"valkey_db0_inventory","exit_code":0,"cardinality_errors":0,"key_count":0,"keys_digest":hashlib.sha256(b"[]").hexdigest()})
        before={"unresolved":[],"tasks":[],"intent_inventory":intent}
        expected={"celery_active did not produce a verifiable response","celery_reserved did not produce a verifiable response","celery_scheduled did not produce a verifiable response","Celery task snapshots do not identify the same single expected worker","Valkey DB0 contains unknown queue state or unverified binding contents"}
        after={"unresolved":[],"classified_raw_unresolved":list(expected),"tasks":[],"intent_inventory":intent,"verification_mode":True,"worker_pid_files_absent":True,"worker_absence_proof":{"passed":True,"process_scan_exit":0,"worker_processes":[],"pid_files":[]},"observations":obs}
        self.assertTrue(validate_verification_queue(before,after)["passed"])
        raw={**after,"unresolved":list(expected)}
        absence=after["worker_absence_proof"]
        self.assertTrue(validate_verification_queue(before,classify_verification_queue(raw,absence))["passed"])
        import copy
        for exit_code in (137, 1, None, 0):
            failed=copy.deepcopy(raw); failed['observations'][0]['exit_code']=exit_code
            with self.assertRaises(ValueError):
                validate_verification_queue(before,classify_verification_queue(failed,absence))
        with self.assertRaises(ValueError):
            classify_verification_queue(raw,{**absence,"worker_processes":["42"]})

        for changed in ({**after,"tasks":[{"id":"unexpected"}]},{**after,"unresolved":["unknown"]}):
            with self.assertRaises(ValueError): validate_verification_queue(before,changed)
        failed={**after,"observations":obs[:-1]+[{**obs[-1],"exit_code":1}]}
        with self.assertRaises(ValueError): validate_verification_queue(before,failed)

    def test_external_controller_resync_persists_authenticated_ack_and_sequence_floor(self):
        with tempfile.TemporaryDirectory() as temp:
            journal = Path(temp) / "journal.json"
            controller = Controller.__new__(Controller)
            controller.config = {"deployment_id": "g7-local",
                "controller_instance_id": "00000000-0000-4000-8000-000000000017"}
            controller.deployment = "g7-local"
            controller.journal = journal
            controller.state = {"schema_version": 1, "deployment_id": "g7-local",
                "controller_instance_id": controller.config["controller_instance_id"],
                "last_sequence": 8, "recovery_epoch_floor": 2,
                "last_intent": None, "last_ack": None}
            def request(path, body):
                self.assertEqual(path, "sequence-resync")
                return {"schema_version": 1, "deployment_id": "g7-local",
                    "resync_id": body["resync_id"], "recovery_epoch_floor": 3,
                    "next_sequence": 9, "accepted": True, "revisions": {"configuration": 2, "host_policy": 1}}
            controller._request = request
            response = controller.resynchronize(database_epoch_seen=2,
                database_sequence_seen=8, checkpoint_epoch_floor=3)
            self.assertTrue(response["accepted"])
            saved = json.loads(journal.read_text())
            self.assertEqual(saved["last_sequence"], 8)
            self.assertEqual(saved["recovery_epoch_floor"], 3)
            self.assertEqual(saved["last_resync"]["response"], response)
            self.assertNotIn("pending_resync", saved)

    def test_external_controller_journals_signed_recovery_event_before_ack(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private = Ed25519PrivateKey.generate()
            private_path, public_path = root / "private.pem", root / "public.pem"
            private_path.write_bytes(private.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            public_path.write_bytes(private.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            journal = root / "journal.json"
            controller = Controller.__new__(Controller)
            controller.config = {"deployment_id": "g7-local",
                "controller_instance_id": "00000000-0000-4000-8000-000000000017",
                "signing_key_id": "test-key", "signing_key_file": str(private_path)}
            controller.deployment, controller.journal = "g7-local", journal
            controller.state = {"schema_version": 1, "deployment_id": "g7-local",
                "controller_instance_id": controller.config["controller_instance_id"],
                "last_sequence": 2, "recovery_epoch_floor": 0,
                "last_intent": None, "last_ack": None}
            unsigned = {"schema_version": 1, "deployment_id": "g7-local",
                "event_id": str(uuid.uuid4()), "recovery_epoch": 1,
                "connector_recovery_id": str(uuid.uuid4()), "previous_epoch": 0,
                "event_type": "restore_started", "archive_id": str(uuid.uuid4()),
                "manifest_digest": "sha256:" + "a" * 64,
                "source_image_digest": "sha256:" + "b" * 64,
                "target_image_digest": None, "new_volume_ids": None,
                "verification": {"uvm_public_api": "not_run", "ce_public_api": "not_run",
                    "media_readback": "not_run", "queue_reconciliation": "not_run",
                    "migration": "not_run", "details_digest": None},
                "queue_inventory_digest": "sha256:" + "c" * 64,
                "public_readback_digest": None, "failure_code": None,
                "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
            invalid_verified = {**unsigned, "event_id": str(uuid.uuid4()),
                "event_type": "verification_passed", "previous_epoch": 1,
                "verification": {"uvm_public_api": "passed", "ce_public_api": "passed",
                    "media_readback": "passed", "queue_reconciliation": "passed",
                    "migration": "passed", "details_digest": None}}
            with self.assertRaises(RecoveryError):
                controller.submit_recovery_event(invalid_verified)
            def request(_path, body):
                self.assertEqual(json.loads(journal.read_text())["pending_recovery_event"], body)
                raw, _ = verify_signature(body, str(public_path), "test-key")
                self.assertEqual(raw, canonical_json({key: value for key, value in body.items()
                    if key != "signature"}))
                return {"accepted": True, "event_id": body["event_id"],
                    "sequence": body["sequence"], "recovery_epoch": body["recovery_epoch"]}
            controller._request = request
            response = controller.submit_recovery_event(unsigned)
            self.assertTrue(response["accepted"])
            saved = json.loads(journal.read_text())
            self.assertEqual(saved["last_sequence"], 3)
            self.assertEqual(saved["recovery_epoch_floor"], 1)
            self.assertNotIn("pending_recovery_event", saved)

    def test_ce_verification_middleware_is_exact_read_only_allowlist(self):
        self.assertEqual(recovery_request_decision("GET", "/api/v2/findings/123/"), "allow")
        self.assertEqual(recovery_request_decision("HEAD", "/api/v2/files/7/"), "allow")
        self.assertEqual(recovery_request_decision("POST", "/api/v2/findings/123/"),
            "method_not_allowed")
        self.assertEqual(recovery_request_decision("GET", "/api/v2/import-scan/"), "not_found")

    def test_uvm_verification_middleware_is_exact_read_only_allowlist(self):
        self.assertEqual(uvm_recovery_request_decision("GET", "/"), "allow")
        self.assertEqual(uvm_recovery_request_decision("GET", "/assets/index-test.js"), "allow")
        self.assertEqual(uvm_recovery_request_decision("POST", "/"), "method_not_allowed")
        self.assertEqual(uvm_recovery_request_decision("GET", "/api/v1/auth/session"), "allow")
        self.assertEqual(uvm_recovery_request_decision("GET",
            "/api/v1/operations/backup-settings"), "allow")
        self.assertEqual(uvm_recovery_request_decision("GET",
            "/api/v1/assessment/groups/00000000-0000-4000-8000-000000000001"), "allow")
        self.assertEqual(uvm_recovery_request_decision("POST",
            "/api/v1/operations/backup-settings"), "method_not_allowed")
        self.assertEqual(uvm_recovery_request_decision("POST",
            "/api/v1/operations/backup-settings/g7-local/commands"), "method_not_allowed")
        self.assertEqual(uvm_recovery_request_decision("GET",
            "/api/v1/auth/login"), "not_found")

    def test_epoch_two_readback_manifest_rejects_missing_or_mismatched_results(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            names=("rollback-public-readback.json", "rollback-uvm-group.json",
                "rollback-uvm-audit.json", "rollback-ce-findings.json",
                "rollback-volume-ids.json", "epoch-2-rollback-readback.json",
                "restore-ce-media.txt", "restore-ce-engagement.json")
            readbacks={}
            for name in names:
                data=("result:"+name).encode(); (root/name).write_bytes(data)
                readbacks[name]=hashlib.sha256(data).hexdigest()
            binding={"recovery_epoch":2,"target_image_digest":"sha256:"+"a"*64,
                "new_volume_ids":{"postgres_cluster":"pg","ce_media":"media","uvm_state":"uvm"}}
            raw=json.dumps(binding,sort_keys=True,separators=(",",":")).encode()
            (root/"rollback-context-binding.json").write_bytes(raw)
            readbacks["rollback-context-binding.json"]=hashlib.sha256(raw).hexdigest()
            (root/"verification-readback-manifest.json").write_text(json.dumps(readbacks))
            digest_value=validate_epoch_two_readbacks(root,readbacks,binding)
            self.assertRegex(digest_value,r"^sha256:[0-9a-f]{64}$")
            (root/"rollback-ce-findings.json").write_text("tampered")
            with self.assertRaisesRegex(ValueError,"mismatched"):
                validate_epoch_two_readbacks(root,readbacks,binding)
            (root/"rollback-ce-findings.json").unlink()
            with self.assertRaisesRegex(ValueError,"missing or mismatched"):
                validate_epoch_two_readbacks(root,readbacks,binding)

    def test_recovery_control_listener_hides_all_product_routes(self):
        self.assertEqual(recovery_control_request_decision(
            "/recovery-control/v1/g7-local/sequence-resync"), "allow")
        self.assertEqual(recovery_control_request_decision("/healthz"), "allow")
        self.assertEqual(recovery_control_request_decision(
            "/api/v1/operations/backup-settings/g7-local"), "not_found")
        self.assertEqual(recovery_control_request_decision("/openapi.json"), "not_found")

    def test_discovery_cursor_binds_policy_authority_registry_and_projection(self):
        secret = b"test-cursor-secret"
        token = _discovery_cursor(secret, principal="actor-stable-id",
            policy_revision=4, authority_revision=8, registry_digest="registry-a",
            visible_digest="projection-a", after=50, limit=50, expires_at=2000)
        self.assertEqual(_read_discovery_cursor(secret, token,
            principal="actor-stable-id", policy_revision=4, authority_revision=8,
            registry_digest="registry-a", visible_digest="projection-a",
            limit=50, now_epoch=1000), 50)
        for changes in ({"policy_revision": 5}, {"visible_digest": "projection-b"},
                {"registry_digest": "registry-b"}, {"authority_revision": 9}):
            args = {"principal": "actor-stable-id", "policy_revision": 4,
                "authority_revision": 8, "registry_digest": "registry-a",
                "visible_digest": "projection-a", "limit": 50, "now_epoch": 1000}
            args.update(changes)
            with self.subTest(changes=changes), self.assertRaises(Exception):
                _read_discovery_cursor(secret, token, **args)

    def test_rejects_unknown_missing_boolean_out_of_bounds_and_unregistered_refs(self):
        variants = [
            {**self.values, "extra": 1},
            {key: value for key, value in self.values.items() if key != "timeout_seconds"},
            {**self.values, "timeout_seconds": True},
            {**self.values, "interval_seconds": 59},
            {**self.values, "archive_target_ref": "/var/lib/unsafe"},
            {**self.values, "recovery_profile_ref": "missing"},
        ]
        for candidate in variants:
            with self.subTest(candidate=candidate), self.assertRaises(ObserverSettingsError):
                validate_backup_values(candidate, self.policy)

    def test_signed_host_policy_uses_canonical_ed25519_and_pinned_key_id(self):
        host_policy = {
            "revision": 1,
            "bounds": self.policy["bounds"],
            "archive_target_refs": ["archive-a"],
            "recovery_profile_refs": ["profile-a"],
            "maximum_report_age_seconds": 300,
            "maximum_future_skew_seconds": 30,
        }
        host_policy["digest"] = "sha256:" + digest(host_policy)
        self.assertEqual(validate_policy(host_policy), host_policy)
        invalid_policy = {**host_policy, "archive_target_refs": ["/var/lib/backups"]}
        invalid_policy["digest"] = "sha256:" + digest({k: v for k, v in invalid_policy.items() if k != "digest"})
        with self.assertRaises(ValueError):
            validate_policy(invalid_policy)
        private = Ed25519PrivateKey.generate()
        document = {"schema_version": 1, "deployment_id": "deploy-a",
            "report_id": "00000000-0000-4000-8000-000000000001", "host_policy": host_policy}
        signature = private.sign(canonical_json(document))
        document["signature"] = {"algorithm": "Ed25519", "key_id": "test-key",
            "value": base64.urlsafe_b64encode(signature).decode().rstrip("=")}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "pub.pem"
            path.write_bytes(private.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            raw, _ = verify_signature(document, str(path), "test-key")
            self.assertEqual(raw, canonical_json({k: v for k, v in document.items() if k != "signature"}))
            with self.assertRaises(ValueError):
                verify_signature(document, str(path), "wrong-key")
        with self.assertRaises(ValueError):
            canonical_json({"time": 1.5})
        with self.assertRaises(ValueError):
            canonical_json({"sequence": 9007199254740992})

    def test_complete_signed_three_member_archive_verifies_and_rejects_damage(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source_dir = root / "sources"
            source_dir.mkdir()
            archive_dir = root / "bundle"
            archive_dir.mkdir()
            private = Ed25519PrivateKey.generate()
            public_path = root / "pub.pem"
            public_path.write_bytes(private.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            members = []
            for name in ("postgres_cluster", "ce_media", "uvm_state"):
                source = source_dir / f"{name}.source"
                source.write_bytes((name + " sentinel").encode())
                archive = archive_dir / f"{name}.tar.gz"
                with tarfile.open(archive, "w:gz") as tar:
                    tar.add(source, arcname="sentinel")
                raw = archive.read_bytes()
                members.append({"name": name, "volume_id": "fixture-" + name,
                    "member": archive.name, "sha256": hashlib.sha256(raw).hexdigest(),
                    "byte_length": len(raw)})
            manifest = {"schema_version": 1, "deployment_id": "deploy-a",
                "archive_id": str(uuid.uuid4()), "generation": 1, "recovery_epoch": 0,
                "capture_started_at": "2026-10-27T12:00:30Z",
                "consistency_point_at": "2026-10-27T12:00:00Z",
                "completed_at": "2026-10-27T12:00:00Z",
                "image_digest": "sha256:" + "a" * 64,
                "package_manifest_digest": "sha256:" + "b" * 64,
                "volumes": members, "settings_revision": 1,
                "settings_digest": "sha256:" + "c" * 64, "host_policy_revision": 1,
                "host_policy_digest": "sha256:" + "d" * 64,
                "controller_instance_id": "00000000-0000-4000-8000-000000000017",
                "controller_sequence": 1, "queue_inventory_digest": "sha256:" + "e" * 64,
                "outcome": "complete"}
            signature = private.sign(canonical_json(manifest))
            manifest["signature"] = {"algorithm": "Ed25519", "key_id": "test-key",
                "value": base64.urlsafe_b64encode(signature).decode().rstrip("=")}
            manifest_path = archive_dir / "manifest.json"
            manifest_path.write_bytes(canonical_json(manifest) + b"\n")
            verified = verify_archive(archive_dir=archive_dir, public_key=public_path,
                deployment_id="deploy-a", image_digest="sha256:" + "a" * 64,
                package_manifest_digest="sha256:" + "b" * 64, expected_key_id="test-key")
            self.assertEqual(verified["archive_id"], manifest["archive_id"])
            def resign(document):
                unsigned = {key: value for key, value in document.items() if key != "signature"}
                signature = private.sign(canonical_json(unsigned))
                return {**unsigned, "signature": {"algorithm": "Ed25519", "key_id": "test-key",
                    "value": base64.urlsafe_b64encode(signature).decode().rstrip("=")}}

            malformed = resign({**manifest, "volumes": [*manifest["volumes"][:2], None]})
            manifest_path.write_bytes(canonical_json(malformed) + b"\n")
            with self.assertRaises(RecoveryError):
                verify_archive(archive_dir=archive_dir, public_key=public_path,
                    deployment_id="deploy-a", image_digest="sha256:" + "a" * 64,
                    package_manifest_digest="sha256:" + "b" * 64, expected_key_id="test-key")
            manifest_path.write_bytes(canonical_json(manifest) + b"\n")
            self.assertRaises(RecoveryError, restore_new_volumes,
                archive_dir=archive_dir, public_key=public_path, deployment_id="deploy-a",
                image_digest="sha256:" + "a" * 64, package_manifest_digest="sha256:" + "b" * 64,
                expected_key_id="test-key", helper_image="unused", name_prefix="../../escape")
            missing = archive_dir / "ce_media.tar.gz"
            original = missing.read_bytes()
            missing.unlink()
            with self.assertRaises(RecoveryError):
                verify_archive(archive_dir=archive_dir, public_key=public_path,
                    deployment_id="deploy-a", image_digest="sha256:" + "a" * 64,
                    package_manifest_digest="sha256:" + "b" * 64, expected_key_id="test-key")
            missing.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
            with self.assertRaises(RecoveryError):
                verify_archive(archive_dir=archive_dir, public_key=public_path,
                    deployment_id="deploy-a", image_digest="sha256:" + "a" * 64,
                    package_manifest_digest="sha256:" + "b" * 64, expected_key_id="test-key")
            missing.write_bytes(original)
            unsafe = root / "unsafe.tar.gz"
            with tarfile.open(unsafe, "w:gz") as tar:
                import io
                item = tarfile.TarInfo("../escape")
                payload = b"unsafe"
                item.size = len(payload)
                tar.addfile(item, io.BytesIO(payload))
            unsafe_bytes = unsafe.read_bytes()
            unsafe_manifest = json.loads(json.dumps(manifest))
            unsafe_member = next(item for item in unsafe_manifest["volumes"] if item["name"] == "ce_media")
            unsafe_member.update(sha256=hashlib.sha256(unsafe_bytes).hexdigest(), byte_length=len(unsafe_bytes))
            (archive_dir / "ce_media.tar.gz").write_bytes(unsafe_bytes)
            manifest_path.write_bytes(canonical_json(resign(unsafe_manifest)) + b"\n")
            with self.assertRaises(RecoveryError):
                verify_archive(archive_dir=archive_dir, public_key=public_path,
                    deployment_id="deploy-a", image_digest="sha256:" + "a" * 64,
                    package_manifest_digest="sha256:" + "b" * 64, expected_key_id="test-key")
            (archive_dir / "ce_media.tar.gz").write_bytes(original)
            manifest_path.write_bytes(canonical_json(manifest) + b"\n")
            calls = []
            def fake_run(argv, **_kwargs):
                calls.append(argv)
                if argv[:3] == ["docker", "image", "inspect"]:
                    return "sha256:" + "a" * 64
                if argv[:3] == ["docker", "volume", "create"]:
                    return argv[-1]
                return ""
            with patch("tools.g7_backup_recovery._run", side_effect=fake_run):
                replacements = restore_new_volumes(archive_dir=archive_dir,
                    public_key=public_path, deployment_id="deploy-a",
                    image_digest="sha256:" + "a" * 64,
                    package_manifest_digest="sha256:" + "b" * 64,
                    expected_key_id="test-key", helper_image="pinned-helper",
                    name_prefix="g7-restore")
            self.assertEqual(set(replacements), {"postgres_cluster", "ce_media", "uvm_state"})
            self.assertEqual(len([call for call in calls if call[:3] == ["docker", "volume", "create"]]), 3)
            self.assertEqual(len([call for call in calls if call[:2] == ["docker", "run"]]), 3)


if __name__ == "__main__":
    unittest.main()
