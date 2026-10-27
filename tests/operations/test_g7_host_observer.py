from __future__ import annotations

from datetime import datetime, timezone
import json
import io
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from tools import g7_host_observer as host
from uvm.operations.api import _discovery_cursor, _read_discovery_cursor


VALUES = {
    "observation_interval_seconds": 1,
    "request_deadline_seconds": 8,
    "heartbeat_freshness_seconds": 3,
    "maximum_future_skew_seconds": 1,
    "anchor_export_lag_seconds": 30,
    "incident_projection_deadline_seconds": 10,
    "scheduler_progress_freshness_seconds": 15,
}
UTC = timezone.utc
BOUNDS = {key: {"min": 0 if key == "maximum_future_skew_seconds" else 1,
    "max": 60} for key in host.FIELDS}


class HostObserverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.reports = []
        self.private_key = Ed25519PrivateKey.generate()
        self.key_file = self.root / "host-signing-key.pem"
        self.key_file.write_bytes(self.private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.token_file = self.root / "host-token"
        self.token_file.write_text("fixture-service-token\n")
        self.policy = {
            "schema_version": 1, "deployment_id": "deploy-a", "revision": 1,
            "bounds": BOUNDS, "freshness_seconds": 60, "poll_seconds": 1,
            "controller_request_timeout_seconds": 2, "apply_deadline_seconds": 1,
            "sink_id": "fixture-sink", "anchor_read_dsn": "postgresql://readonly.invalid/anchors",
            "endpoint": "https://observer.example.invalid", "token_file": str(self.token_file),
            "signing_key_file": str(self.key_file), "state_dir": str(self.root / "host-state"),
            "active_file": str(self.root / "host-state" / "active.json"),
            "scheduler_file": str(self.root / "scheduler.json"),
            "observer_readback": str(self.root / "readback" / "observer.json"),
            "supervisor_readback": str(self.root / "readback" / "supervisor.json"),
            "observer_state": str(self.root / "state" / "observer.json"),
            "supervisor_state": str(self.root / "state" / "supervisor.json"),
        }
        self.policy["host_policy_digest"] = host.digest(self.policy)

    def tearDown(self):
        self.temp.cleanup()

    def _desired(self, values=None):
        values = values or VALUES
        return {"revision": 1, "digest": host.digest(values), "values": values,
            "command_id": "00000000-0000-4000-8000-000000000001",
            "intent_id": "00000000-0000-4000-8000-000000000002",
            "expected_host_policy_revision": 1}

    def test_policy_and_independent_bounds_reject_booleans_and_missing_fields(self):
        self.assertEqual(host.validate_policy(self.policy), self.policy)
        self.assertEqual(host.validate_values(VALUES, BOUNDS), VALUES)
        invalid = dict(VALUES, observation_interval_seconds=True)
        with self.assertRaises(ValueError):
            host.validate_values(invalid, BOUNDS)
        with self.assertRaises(ValueError):
            host.validate_values({key: value for key, value in VALUES.items() if key != "anchor_export_lag_seconds"}, BOUNDS)
        changed_policy = dict(self.policy, poll_seconds=0)
        changed_policy["host_policy_digest"] = host.digest({k: v for k, v in changed_policy.items() if k != "host_policy_digest"})
        with self.assertRaises(ValueError):
            host.validate_policy(changed_policy)

    def test_deployment_cursor_binds_actor_authority_registry_and_visible_grants(self):
        args = {"principal": "operator-a", "authority_revision": 7,
            "registry_digest": "registry-a", "visible_digest": "grants-a",
            "after": 3, "limit": 2, "expires_at": 1000}
        token = _discovery_cursor(b"cursor-secret", **args)
        common = {key: args[key] for key in (
            "principal", "authority_revision", "registry_digest", "visible_digest", "limit")}
        self.assertEqual(_read_discovery_cursor(b"cursor-secret", token,
            **common, now_epoch=999), 3)
        for changed in ({"principal": "operator-b"}, {"authority_revision": 8},
                {"registry_digest": "registry-b"}, {"visible_digest": "grants-b"},
                {"limit": 3}):
            bound = {**common, **changed}
            with self.assertRaises(Exception):
                _read_discovery_cursor(b"cursor-secret", token, **bound, now_epoch=999)
        with self.assertRaises(Exception):
            _read_discovery_cursor(b"cursor-secret", token, **common, now_epoch=1001)

    def test_controller_requires_two_matching_consumer_readbacks(self):
        desired = self._desired()
        def fake_request(url, token, timeout, body=None):
            self.assertEqual(token, "fixture-service-token")
            self.assertLessEqual(timeout, 8)
            if body is None:
                return {"schema_version": 1, "deployment_id": "deploy-a", "desired": desired}
            self.reports.append(body)
            return {"schema_version": 1, "report_id": body["report_id"],
                "sequence": body["sequence"], "accepted": True, "duplicate": False}
        for role in ("observer", "supervisor"):
            host.atomic_json(Path(self.policy[role + "_readback"]), {
                "revision": 1, "digest": desired["digest"],
                "observed_at": "2020-01-01T00:00:00Z"})
        refreshed = False
        def complete_consumer_loops(_seconds):
            nonlocal refreshed
            if not refreshed:
                for role in ("observer", "supervisor"):
                    host.atomic_json(Path(self.policy[role + "_readback"]), {
                        "revision": 1, "digest": desired["digest"],
                        "observed_at": host.utc_now()})
                refreshed = True

        with patch.object(host, "request_json", side_effect=fake_request), \
             patch.object(host.time, "sleep", side_effect=complete_consumer_loops):
            result = host.controller_once(self.policy)
        self.assertEqual(result["status"], "applied")
        self.assertEqual(len(self.reports), 0, "report must be journalled before network submission")
        pending = host.read_json(Path(self.policy["state_dir"]) / "journal.json")["pending_report"]
        self.assertEqual(pending["outcome"], "applied")
        self.assertEqual(pending["consumers"]["observer"]["digest"], desired["digest"])
        signed = {key: value for key, value in pending.items() if key != "signature"}
        signature = pending["signature"] + "=" * (-len(pending["signature"]) % 4)
        public_key = self.private_key.public_key()
        public_key.verify(__import__("base64").urlsafe_b64decode(signature), host.canonical(signed))

        # A second pass submits the exact stored report and gets its receipt.
        with patch.object(host, "request_json", side_effect=fake_request):
            self.assertEqual(host.controller_once(self.policy)["status"], "applied")
        self.assertEqual(len(self.reports), 1)
        self.assertEqual(self.reports[0]["report_id"], pending["report_id"])

    def test_out_of_bounds_candidate_is_reported_failed_and_never_installed(self):
        invalid = dict(VALUES, request_deadline_seconds=61)
        desired = self._desired(invalid)
        def fake_request(_url, _token, _timeout, _body=None):
            return {"schema_version": 1, "deployment_id": "deploy-a", "desired": desired}
        with patch.object(host, "request_json", side_effect=fake_request):
            result = host.controller_once(self.policy)
        self.assertEqual(result["status"], "failed")
        self.assertIsNone(host.read_json(Path(self.policy["active_file"])))
        journal = host.read_json(Path(self.policy["state_dir"]) / "journal.json")
        self.assertEqual(journal["pending_report"]["failure_code"], "host_policy_rejected")

    def test_preexisting_matching_readbacks_cannot_confirm_a_new_candidate(self):
        desired = self._desired()
        for role in ("observer", "supervisor"):
            host.atomic_json(Path(self.policy[role + "_readback"]), {
                "revision": desired["revision"], "digest": desired["digest"],
                "observed_at": "2020-01-01T00:00:00Z"})
        with patch.object(host, "request_json", return_value={
                "schema_version": 1, "deployment_id": "deploy-a", "desired": desired}), \
             patch.object(host.time, "sleep", return_value=None):
            result = host.controller_once(self.policy)
        self.assertEqual(result["status"], "uncertain")
        self.assertIsNone(host.read_json(Path(self.policy["active_file"])))
        journal = host.read_json(Path(self.policy["state_dir"]) / "journal.json")
        self.assertNotIn("last_good", journal)

    def test_expired_applied_report_never_refreshes_stale_consumer_timestamps(self):
        desired = self._desired()
        stale_stamp = "2020-01-01T00:00:00Z"
        for role in ("observer", "supervisor"):
            host.atomic_json(Path(self.policy[role + "_readback"]), {
                "revision": desired["revision"], "digest": desired["digest"],
                "observed_at": stale_stamp})
        prior = host._report(self.policy, {"sequence": 1, "last_good": None},
            desired, "applied", None)
        self.assertEqual(prior["outcome"], "uncertain")
        # Exercise an expired report that claimed applied in its original
        # record: its stale consumer timestamps must stay stale on retry.
        prior["outcome"] = "applied"
        prior["active_revision"] = desired["revision"]
        prior["active_digest"] = desired["digest"]
        prior = host.signed_report(self.policy,
            {key: value for key, value in prior.items() if key != "signature"})
        host.atomic_json(Path(self.policy["token_file"]), "test-token\n")

        def expired():
            return urllib.error.HTTPError("https://host.invalid/reports", 400,
                "rejected", {}, io.BytesIO(json.dumps({"detail": {"code": "report_expired"}}).encode()))

        host.atomic_json(Path(self.policy["state_dir"]) / "journal.json", {
            "sequence": 1, "pending_report": prior})
        posts = []

        def stale_request(_url, _token, _timeout, body=None):
            if body is None:
                return {"schema_version": 1, "deployment_id": "deploy-a", "desired": None}
            posts.append(body)
            raise expired()

        with patch.object(host, "request_json", side_effect=stale_request):
            result = host.controller_once(self.policy)
        self.assertEqual(result, {"status": "uncertain", "failure_code": "consumer_readback_stale"})
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0]["consumers"]["observer"]["observed_at"], stale_stamp)
        self.assertEqual(posts[0]["consumers"]["supervisor"]["observed_at"], stale_stamp)
        journal = host.read_json(Path(self.policy["state_dir"]) / "journal.json")
        self.assertEqual(journal["pending_report"]["consumers"]["observer"]["observed_at"], stale_stamp)

        for role in ("observer", "supervisor"):
            host.atomic_json(Path(self.policy[role + "_readback"]), {
                "revision": desired["revision"], "digest": desired["digest"],
                "observed_at": host.utc_now()})

        def accept_fresh(_url, _token, _timeout, body=None):
            if body is None:
                return {"schema_version": 1, "deployment_id": "deploy-a", "desired": None}
            if not host._consumer_readbacks_fresh(body["consumers"], self.policy["freshness_seconds"]):
                raise expired()
            return {"schema_version": 1, "report_id": body["report_id"],
                "sequence": body["sequence"], "accepted": True, "duplicate": False}

        with patch.object(host, "request_json", side_effect=accept_fresh):
            host.controller_once(self.policy)
        journal = host.read_json(Path(self.policy["state_dir"]) / "journal.json")
        self.assertTrue(journal["last_acknowledgement"]["accepted"])

    def test_missing_readback_uses_parseable_stale_sentinel(self):
        item = host.readback(Path(self.policy["observer_readback"]))
        self.assertIsNone(item["revision"])
        self.assertIsNone(item["digest"])
        self.assertEqual(item["observed_at"], "1970-01-01T00:00:00Z")
        self.assertFalse(host._consumer_readbacks_fresh({"observer": item},
            self.policy["freshness_seconds"]))

    def test_superseded_pending_report_reconciles(self):
        desired = self._desired()
        prior = host._report(self.policy, {"sequence": 1, "last_good": None},
            desired, "failed", "host_policy_rejected")
        host.atomic_json(Path(self.policy["token_file"]), "test-token\n")
        host.atomic_json(Path(self.policy["state_dir"]) / "journal.json", {
            "sequence": 1, "pending_report": prior})

        def superseded(_url, _token, _timeout, body=None):
            if body is None:
                return {"schema_version": 1, "deployment_id": "deploy-a", "desired": None}
            raise urllib.error.HTTPError("https://host.invalid/reports", 409, "rejected", {},
                io.BytesIO(json.dumps({"detail": {"code": "report_superseded"}}).encode()))

        with patch.object(host, "request_json", side_effect=superseded):
            self.assertEqual(host.controller_once(self.policy)["status"], "uncertain")
        journal = host.read_json(Path(self.policy["state_dir"]) / "journal.json")
        self.assertEqual(journal["superseded_report"]["report_id"], prior["report_id"])

    def test_observer_runs_http_request_with_selected_deadline_and_scheduler_check(self):
        desired = self._desired()
        host.atomic_json(Path(self.policy["active_file"]), {"schema_version": 1,
            "revision": 1, "digest": desired["digest"], "values": VALUES})
        host.atomic_json(Path(self.policy["scheduler_file"]), {"loop_sequence": 5,
            "monotonic_ns": time.monotonic_ns(), "boot_id":
                Path("/proc/sys/kernel/random/boot_id").read_text().strip()})
        observed = []
        def fake_probe(url, token, timeout):
            observed.append((url, token, timeout))
            return 200, {"schema_version": 1, "deployment_id": "deploy-a",
                "sink_id": "fixture-sink", "audit_events": [], "audit_complete": True,
                "incidents": [], "incidents_complete": True}, None
        started = time.monotonic()
        with patch.object(host, "_request", side_effect=fake_probe), \
             patch.object(host, "read_anchor_inventory", return_value={}) as anchors:
            result = host.consumer_once("observer", self.policy)
        anchors.assert_called_once_with("postgresql://readonly.invalid/anchors",
            "deploy-a", "fixture-sink", [], VALUES["request_deadline_seconds"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(observed[0][2], VALUES["request_deadline_seconds"])
        state = host.read_json(Path(self.policy["observer_state"]))
        self.assertLess(time.monotonic() - started, VALUES["request_deadline_seconds"])
        self.assertEqual(state["scheduler"]["status"], "healthy")
        self.assertEqual(state["last_check"]["anchor_export"]["status"], "healthy")
        self.assertEqual(state["last_check"]["incident_projection"]["status"], "healthy")
        self.assertIn("/host/telemetry?limit=1000&sink_id=fixture-sink", observed[0][0])
        self.assertEqual(host.read_json(Path(self.policy["observer_readback"]))["digest"], desired["digest"])

    def test_observer_marks_a_stalled_scheduler_nonprogressing(self):
        desired = self._desired()
        host.atomic_json(Path(self.policy["active_file"]), {"schema_version": 1,
            "revision": 1, "digest": desired["digest"], "values": VALUES})
        host.atomic_json(Path(self.policy["scheduler_file"]), {"loop_sequence": 7,
            "monotonic_ns": time.monotonic_ns(), "boot_id":
                Path("/proc/sys/kernel/random/boot_id").read_text().strip()})
        with patch.object(host, "_request", return_value=(200, {
                "schema_version": 1, "deployment_id": "deploy-a", "audit_events": [],
                "audit_complete": True, "incidents": [], "incidents_complete": True}, None)), \
             patch.object(host, "read_anchor_inventory", return_value={}):
            host.consumer_once("observer", self.policy)
            state_before = host.read_json(Path(self.policy["observer_state"]))
            host.consumer_once("observer", self.policy)
            state_repeat = host.read_json(Path(self.policy["observer_state"]))
            with patch.object(host.time, "monotonic_ns",
                    return_value=time.monotonic_ns() + 16_000_000_000):
                host.consumer_once("observer", self.policy)
        state_after = host.read_json(Path(self.policy["observer_state"]))
        self.assertEqual(state_before["scheduler"]["status"], "healthy")
        self.assertEqual(state_repeat["scheduler"]["status"], "healthy")
        self.assertLess(state_repeat["scheduler"]["age_seconds"], 15)
        self.assertEqual(state_after["scheduler"]["status"], "stale_or_nonprogressing")
        self.assertEqual(state_after["loop_sequence"], state_before["loop_sequence"] + 2)

    def test_observer_resets_retained_scheduler_progress_only_for_current_new_boot(self):
        desired = self._desired()
        host.atomic_json(Path(self.policy["active_file"]), {"schema_version": 1,
            "revision": 1, "digest": desired["digest"], "values": VALUES})
        state_path = Path(self.policy["observer_state"])
        host.atomic_json(state_path, {"scheduler_progress_boot_id": "old-boot",
            "scheduler_loop_sequence": 100000000000,
            "scheduler_last_progress_monotonic_ns": 100000000000})
        response = (200, {"schema_version": 1, "deployment_id": "deploy-a",
            "audit_events": [], "audit_complete": True,
            "incidents": [], "incidents_complete": True}, None)
        with patch.object(host, "_host_boot_id", return_value="new-boot"), \
             patch.object(host, "_request", return_value=response), \
             patch.object(host, "read_anchor_inventory", return_value={}):
            for sequence, tick in ((2, 2_000_000_000), (3, 3_000_000_000)):
                host.atomic_json(Path(self.policy["scheduler_file"]), {
                    "loop_sequence": sequence, "monotonic_ns": tick, "boot_id": "new-boot"})
                with patch.object(host.time, "monotonic_ns", return_value=tick):
                    host.consumer_once("observer", self.policy)
                state = host.read_json(state_path)
                self.assertEqual(state["scheduler"]["status"], "healthy")
                self.assertEqual(state["scheduler_loop_sequence"], sequence)
                self.assertEqual(state["scheduler_progress_boot_id"], "new-boot")

    def test_stale_or_malformed_new_boot_samples_do_not_reset_retained_baseline(self):
        desired = self._desired()
        host.atomic_json(Path(self.policy["active_file"]), {"schema_version": 1,
            "revision": 1, "digest": desired["digest"], "values": VALUES})
        state_path = Path(self.policy["observer_state"])
        initial = {"scheduler_progress_boot_id": "old-boot",
            "scheduler_loop_sequence": 100000000000,
            "scheduler_last_progress_monotonic_ns": 100000000000}
        host.atomic_json(state_path, initial)
        response = (200, {"schema_version": 1, "deployment_id": "deploy-a",
            "audit_events": [], "audit_complete": True,
            "incidents": [], "incidents_complete": True}, None)
        samples = [
            {"loop_sequence": 1, "monotonic_ns": 1, "boot_id": "new-boot"},
            {"loop_sequence": "2", "monotonic_ns": 2_000_000_000, "boot_id": "new-boot"},
            {"loop_sequence": 2, "monotonic_ns": 2_000_000_000, "boot_id": "other-boot"},
        ]
        with patch.object(host, "_host_boot_id", return_value="new-boot"), \
             patch.object(host, "_request", return_value=response), \
             patch.object(host, "read_anchor_inventory", return_value={}):
            for sample in samples:
                host.atomic_json(Path(self.policy["scheduler_file"]), sample)
                with patch.object(host.time, "monotonic_ns", return_value=20_000_000_000):
                    host.consumer_once("observer", self.policy)
                state = host.read_json(state_path)
                self.assertEqual(state["scheduler_progress_boot_id"], "old-boot")
                self.assertEqual(state["scheduler_loop_sequence"], 100000000000)
                self.assertEqual(state["scheduler_last_progress_monotonic_ns"], 100000000000)

    def test_supervisor_uses_selected_future_skew_and_preserves_work_across_revision(self):
        first = self._desired()
        state_path = Path(self.policy["observer_state"])
        state_path.parent.mkdir(parents=True)
        host.atomic_json(state_path, {"loop_sequence": 9,
            "last_completed_loop_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "incidents": ["open-event"], "pending_work": ["host-reconcile"]})
        host.atomic_json(Path(self.policy["active_file"]), {"schema_version": 1,
            "revision": 1, "digest": first["digest"], "values": VALUES})
        result = host.consumer_once("supervisor", self.policy)
        self.assertEqual(result["status"], "completed")
        state = host.read_json(Path(self.policy["supervisor_state"]))
        self.assertEqual(state["supervision"]["status"], "healthy")
        self.assertEqual(state["supervision"]["maximum_future_skew_seconds"], 1)
        self.assertEqual(state["loop_sequence"], 1)
        observer_state = host.read_json(state_path)
        self.assertEqual(observer_state["incidents"], ["open-event"])
        self.assertEqual(observer_state["pending_work"], ["host-reconcile"])

        observer_state["last_completed_loop_at"] = (
            datetime.fromtimestamp(datetime.now(UTC).timestamp() + 20, UTC)
            .isoformat().replace("+00:00", "Z"))
        host.atomic_json(state_path, observer_state)
        result = host.consumer_once("supervisor", self.policy)
        self.assertEqual(result["status"], "completed")
        state = host.read_json(Path(self.policy["supervisor_state"]))
        self.assertEqual(state["supervision"]["status"], "stale_or_future")

    def test_lag_measurement_detects_unanchored_and_late_incident_projection(self):
        now = datetime(2026, 10, 27, 16, 0, tzinfo=UTC)
        telemetry = {"audit_complete": True, "incidents_complete": True,
            "audit_events": [{"event_id": "event-1", "event_digest": "a" * 64,
                "sink_receipt": "receipt-a", "received_at": "2026-10-27T15:59:20Z"}],
            "incidents": [{"observed_at": "2026-10-27T15:59:40Z",
                "projected_at": "2026-10-27T15:59:48Z"}]}
        anchors = {"event-1": {"payload_sha256": "b" * 64,
            "sink_receipt": "receipt-a", "anchored_at": "2026-10-27T15:59:55Z"}}
        result = host.measure_lag(telemetry, anchors, VALUES, now)
        self.assertEqual(result["anchor_export"]["status"], "late")
        self.assertEqual(result["anchor_export"]["receipt_or_digest_mismatch_count"], 1)
        self.assertEqual(result["anchor_export"]["maximum_pending_lag_seconds"], 40)
        self.assertEqual(result["anchor_export"]["maximum_export_lag_seconds"], 0)
        self.assertEqual(result["incident_projection"]["status"], "healthy")
        self.assertEqual(result["incident_projection"]["maximum_projection_lag_seconds"], 8)

        telemetry["incidents"][0]["projected_at"] = "2026-10-27T16:00:00Z"
        result = host.measure_lag(telemetry, anchors, VALUES, now)
        self.assertEqual(result["incident_projection"]["status"], "late")

        anchors["event-1"]["payload_sha256"] = "a" * 64
        result = host.measure_lag(telemetry, anchors, VALUES, now)
        self.assertEqual(result["anchor_export"]["status"], "late")
        self.assertEqual(result["anchor_export"]["pending_or_unanchored_count"], 0)
        self.assertEqual(result["anchor_export"]["maximum_export_lag_seconds"], 35)

    def test_missing_or_future_telemetry_fails_closed(self):
        now = datetime(2026, 10, 27, 16, 0, tzinfo=UTC)
        telemetry = {"audit_complete": False, "incidents_complete": True,
            "audit_events": [], "incidents": [{"observed_at": "2026-10-27T16:00:05Z",
                "projected_at": None}]}
        result = host.measure_lag(telemetry, {}, VALUES, now)
        self.assertEqual(result["anchor_export"]["status"], "unknown")
        self.assertEqual(result["incident_projection"]["timestamp_anomaly_count"], 1)
        self.assertEqual(result["incident_projection"]["status"], "unknown")
        telemetry["audit_complete"] = True
        telemetry["audit_events"] = [{"event_id": "event-future", "event_digest": "f" * 64,
            "sink_receipt": "receipt-future", "received_at": "2026-10-27T15:59:00Z"}]
        anchors = {"event-future": {"payload_sha256": "f" * 64,
            "sink_receipt": "receipt-future", "anchored_at": "2026-10-27T16:00:10Z"}}
        result = host.measure_lag(telemetry, anchors, VALUES, now)
        self.assertEqual(result["anchor_export"]["status"], "unknown")
        self.assertEqual(result["anchor_export"]["timestamp_anomaly_count"], 1)

    def test_missing_anchor_receipt_persists_finite_unknown_measurement(self):
        now = datetime(2026, 10, 27, 16, 0, tzinfo=UTC)
        telemetry = {"audit_complete": True, "incidents_complete": True,
            "audit_events": [{"event_id": "event-missing-receipt", "event_digest": "a" * 64,
                "sink_receipt": None, "received_at": "2026-10-27T15:59:30Z"}],
            "incidents": []}
        result = host.measure_lag(telemetry, {}, VALUES, now)
        encoded = json.dumps(result, allow_nan=False)
        path = Path(self.policy["state_dir"]) / "measurement.json"
        host.atomic_json(path, result)
        self.assertEqual(json.loads(encoded), host.read_json(path))
        self.assertEqual(result["anchor_export"]["status"], "unknown")
        self.assertEqual(result["anchor_export"]["missing_receipt_count"], 1)
        self.assertEqual(result["anchor_export"]["maximum_pending_lag_seconds"], 30)


if __name__ == "__main__":
    unittest.main()
