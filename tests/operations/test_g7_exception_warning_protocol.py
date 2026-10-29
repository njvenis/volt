"""Focused protocol coverage for G7 exception warning callbacks."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import unittest
from unittest.mock import patch
from datetime import datetime, timezone
from urllib.parse import urlencode

import sqlalchemy as sa


class ExceptionWarningCallbackProtocolTests(unittest.TestCase):
    def setUp(self):
        from uvm.persistence.exception_sla_schema import exception_warning_callback_inbox
        self.engine = sa.create_engine("sqlite://")
        exception_warning_callback_inbox.create(self.engine)
        self.installation_id = "fixture-installation"
        self.secret = "synthetic-signing-secret"
        self.timestamp = str(int(time.time()))
        self.payload = {
            "api_app_id": "fixture-app",
            "team": {"id": "T_FIXTURE"},
            "user": {"id": "U_FIXTURE"},
            "actions": [{"action_id": "uvm_warning_ack", "value": "opaque-action-token"}],
            "container": {"channel_id": "C_FIXTURE"},
            "message": {"ts": "1234567890.000001"},
        }
        self.raw = urlencode({"payload": json.dumps(self.payload, separators=(",", ":"))}).encode()
        base = b"v0:" + self.timestamp.encode() + b":" + self.raw
        self.signature = "v0=" + hmac.new(self.secret.encode(), base, hashlib.sha256).hexdigest()

    def tearDown(self):
        self.engine.dispose()

    def receive(self, *, raw=None, timestamp=None, signature=None, unix_now=None):
        from uvm.assessment.exception_warning_callbacks import receive_signed_slack_callback
        with self.engine.begin() as connection:
            return receive_signed_slack_callback(connection,
                raw_body=self.raw if raw is None else raw,
                timestamp=self.timestamp if timestamp is None else timestamp,
                signature=self.signature if signature is None else signature,
                signing_secret=self.secret, installation_id=self.installation_id,
                now=datetime.now(timezone.utc), unix_now=unix_now)

    def test_signed_raw_body_is_retained_once_and_exact_replay_is_idempotent(self):
        first = self.receive()
        replay = self.receive()
        self.assertFalse(first["duplicate"])
        self.assertTrue(replay["duplicate"])
        self.assertEqual(first["inbox_id"], replay["inbox_id"])
        self.assertEqual(first["state"], "received")

    def test_mutated_body_and_forged_signature_are_rejected_without_inbox_write(self):
        from uvm.assessment.exception_warning_callbacks import InvalidSlackCallback
        changed = self.raw + b" "
        with self.assertRaises(InvalidSlackCallback):
            self.receive(raw=changed)
        forged = "v0=" + "0" * 64
        with self.assertRaises(InvalidSlackCallback):
            self.receive(signature=forged)
        with self.engine.connect() as connection:
            count = connection.execute(sa.text(
                "select count(*) from exception_warning_callback_inbox")).scalar_one()
        self.assertEqual(count, 0)

    def test_stale_signed_body_is_rejected(self):
        from uvm.assessment.exception_warning_callbacks import InvalidSlackCallback
        with self.assertRaises(InvalidSlackCallback):
            self.receive(unix_now=float(self.timestamp) + 301)
        with self.engine.connect() as connection:
            count = connection.execute(sa.text(
                "select count(*) from exception_warning_callback_inbox")).scalar_one()
        self.assertEqual(count, 0)

    def test_warning_actor_link_requires_a_persisted_enabled_human_principal(self):
        from uvm.assessment.api import _warning_human_principal_is_enabled
        from uvm.persistence.auth_schema import auth_principals
        auth_principals.create(self.engine)
        now = datetime.now(timezone.utc)
        with self.engine.begin() as connection:
            connection.execute(auth_principals.insert(), [
                {"principal_id": "fixture-human", "display_label": "Fixture human",
                    "enabled": True, "revision": 1, "created_at": now},
                {"principal_id": "fixture-disabled", "display_label": "Disabled human",
                    "enabled": False, "revision": 1, "created_at": now},
            ])
            self.assertTrue(_warning_human_principal_is_enabled(connection, "fixture-human"))
            self.assertFalse(_warning_human_principal_is_enabled(connection, "fixture-disabled"))
            self.assertFalse(_warning_human_principal_is_enabled(connection, "not-configured"))


class ExceptionWarningSMTPStageTests(unittest.TestCase):
    def setUp(self):
        from uvm.assessment.exception_warning_transports import Destination
        self.target = Destination(channel="email", secret_ref="secret:fixture",
            smtp_host="127.0.0.1", smtp_port=465, smtp_user="fixture",
            sender="sender@fixture.invalid", recipient="recipient@fixture.invalid",
            smtp_tls="implicit")
        self.payload = {"intent_id":"intent-1", "rendered":{
            "subject":"test", "text":"body", "html":"<p>body</p>"}}

    def send_with(self, client=None, constructor_error=None):
        from uvm.assessment.exception_warning_transports import HttpAdapter
        with patch("uvm.assessment.exception_warning_transports.ssl.create_default_context", return_value=object()):
            if constructor_error:
                with patch("uvm.assessment.exception_warning_transports.smtplib.SMTP_SSL", side_effect=constructor_error):
                    return HttpAdapter._send_email(self.target, "secret", self.payload)
            with patch("uvm.assessment.exception_warning_transports.smtplib.SMTP_SSL", return_value=client):
                return HttpAdapter._send_email(self.target, "secret", self.payload)

    def test_pre_data_disconnects_are_known_retryable_failures(self):
        from uvm.assessment.exception_warning_transports import DeliveryError

        class Peer:
            def __init__(self, stage): self.stage = stage
            def login(self, *_):
                if self.stage == "login": raise __import__("smtplib").SMTPServerDisconnected()
            def mail(self, *_):
                if self.stage == "mail": raise __import__("smtplib").SMTPServerDisconnected()
                return 250, b"ok"
            def rcpt(self, *_):
                if self.stage == "rcpt": raise __import__("smtplib").SMTPServerDisconnected()
                return 250, b"ok"
            def data(self, *_): raise AssertionError("DATA must not run in a pre-DATA test")
            def close(self): pass

        for stage in ("connect", "login", "mail", "rcpt"):
            with self.subTest(stage=stage), self.assertRaises(DeliveryError) as caught:
                self.send_with(constructor_error=ConnectionRefusedError() if stage == "connect" else None,
                    client=Peer(stage))
            self.assertFalse(caught.exception.permanent)

    def test_data_disconnect_is_uncertain_but_final_250_survives_quit_failure(self):
        import smtplib
        from uvm.assessment.exception_warning_transports import DeliveryUncertain

        class Peer:
            def __init__(self, data_error=None): self.data_error = data_error
            def login(self, *_): pass
            def mail(self, *_): return 250, b"ok"
            def rcpt(self, *_): return 250, b"ok"
            def data(self, *_):
                if self.data_error: raise self.data_error
                return 250, b"queued"
            def quit(self): raise smtplib.SMTPServerDisconnected()
            def close(self): pass

        with self.assertRaises(DeliveryUncertain):
            self.send_with(client=Peer(smtplib.SMTPServerDisconnected()))
        self.assertTrue(self.send_with(client=Peer()).startswith("smtp_accepted|"))

    def test_explicit_451_response_remains_a_retryable_rejection(self):
        import smtplib
        from uvm.assessment.exception_warning_transports import DeliveryError

        class Peer:
            def login(self, *_): pass
            def mail(self, *_): return 250, b"ok"
            def rcpt(self, *_): return 451, b"temporary"
            def close(self): pass

        with self.assertRaises(DeliveryError) as caught:
            self.send_with(client=Peer())
        self.assertFalse(caught.exception.permanent)


if __name__ == "__main__":
    unittest.main()
