"""Configurable Slack/email HTTP adapters with secret values kept out of records."""
from __future__ import annotations

import json
import html
import hashlib
import os
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.policy import SMTP
import time
import urllib.error
import urllib.request
import urllib.parse
import uuid
from dataclasses import dataclass
from typing import Protocol


class DeliveryError(RuntimeError):
    """Definitive rejection; it is safe to schedule a bounded retry."""

    def __init__(self, message, *, retry_after_seconds=None, permanent=False):
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds
        self.permanent = permanent


class DeliveryUncertain(RuntimeError):
    """The request may have been accepted; do not resend without reconciliation."""


class Adapter(Protocol):
    def send(self, *, channel: str, destination_ref: str, payload: dict) -> str: ...


@dataclass(frozen=True)
class Destination:
    channel: str
    secret_ref: str
    endpoint: str | None = None
    installation_id: str | None = None
    workspace_id: str | None = None
    channel_id: str | None = None
    usergroup_ids: tuple[str, ...] = ()
    link: str | None = None
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_user: str | None = None
    sender: str | None = None
    recipient: str | None = None
    smtp_tls: str | None = None


class HttpAdapter:
    def __init__(self, destinations: dict[str, Destination]):
        self.destinations = destinations

    @classmethod
    def from_environment(cls):
        raw = os.environ.get("UVM_EXCEPTION_WARNING_DESTINATIONS", "{}")
        try:
            config = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("warning destination configuration is invalid") from exc
        if not isinstance(config, dict):
            raise RuntimeError("warning destination configuration is invalid")
        result = {}
        for ref, value in config.items():
            if not isinstance(ref, str) or not isinstance(value, dict):
                raise RuntimeError("warning destination configuration is invalid")
            common = {"channel", "secret_ref"}
            channel = value.get("channel")
            allowed = (common | {"endpoint", "installation_id", "workspace_id", "channel_id",
                "usergroup_ids", "link"} if channel == "slack" else common | {
                "smtp_host", "smtp_port", "smtp_user", "sender", "recipient", "smtp_tls"})
            if (channel not in {"slack", "email"} or not common <= value.keys()
                    or value.keys() - allowed
                    or not re.fullmatch(r"secret:[A-Za-z0-9_.-]{1,100}", value["secret_ref"])):
                raise RuntimeError("warning destination configuration is invalid")
            if channel == "slack":
                endpoint = value.get("endpoint", "https://slack.com/api/chat.postMessage")
                disposable = os.environ.get("UVM_G7_DISPOSABLE_MODE") == "1"
                is_loopback = isinstance(endpoint, str) and bool(re.fullmatch(r"http://(?:127\.0\.0\.1|localhost)(?::[0-9]{1,5})?/[^#]*", endpoint))
                if (not isinstance(endpoint, str) or not (endpoint == "https://slack.com/api/chat.postMessage"
                        or disposable and is_loopback)
                        or not all(isinstance(value.get(key), str) and value[key]
                            for key in ("installation_id", "workspace_id", "channel_id"))):
                    raise RuntimeError("warning Slack destination configuration is invalid")
                groups = value.get("usergroup_ids", [])
                if not isinstance(groups, list) or any(not isinstance(item, str)
                        or not re.fullmatch(r"S[A-Z0-9]{2,30}", item) for item in groups):
                    raise RuntimeError("warning Slack mention configuration is invalid")
                value = {**value, "endpoint": endpoint, "usergroup_ids": tuple(groups)}
            else:
                if (not all(isinstance(value.get(key), str) and value[key]
                        for key in ("smtp_host", "smtp_user", "sender", "recipient"))
                        or type(value.get("smtp_port")) is not int or not 1 <= value["smtp_port"] <= 65535
                        or value.get("smtp_tls") not in {"starttls", "implicit"}):
                    raise RuntimeError("warning SMTP destination configuration is invalid")
                if os.environ.get("UVM_EXCEPTION_WARNING_USE_LOOPBACK_HTTP") == "1" \
                        and value["smtp_host"] not in {"localhost", "127.0.0.1", "::1"}:
                    raise RuntimeError("disposable SMTP fixture must use a loopback host")
            result[ref] = Destination(**value)
        return cls(result)

    def send(self, *, channel: str, destination_ref: str, payload: dict) -> str:
        target = self.destinations.get(destination_ref)
        if target is None or target.channel != channel:
            raise DeliveryError("configured destination is unavailable")
        filename = target.secret_ref.removeprefix("secret:")
        try:
            with open("/run/uvm-g7-secrets/exception-warning/" + filename, encoding="utf-8") as secret_file:
                secret = secret_file.read().strip()
        except OSError:
            raise DeliveryError("configured destination credential is unavailable", permanent=True) from None
        if not secret:
            raise DeliveryError("configured destination credential is unavailable", permanent=True)
        approved = payload.get("approved_destination")
        rendered = payload.get("rendered")
        digest = payload.get("rendered_digest")
        if (not isinstance(approved, dict) or not isinstance(rendered, dict)
                or not isinstance(digest, str)
                or hashlib.sha256(json.dumps(rendered, sort_keys=True,
                    separators=(",", ":")).encode()).hexdigest() != digest
                or approved.get("destination_ref") != destination_ref
                or approved.get("channel") != channel):
            raise DeliveryError("approved warning envelope is unavailable", permanent=True)
        if channel == "email":
            if (approved.get("email_recipient") != target.recipient
                    or approved.get("expires_at") is None
                    or approved.get("link") != rendered.get("link")):
                raise DeliveryError("SMTP destination differs from approved warning envelope", permanent=True)
            return self._send_email(target, secret, payload)
        if (approved.get("installation_id") != target.installation_id
                or approved.get("workspace_id") != target.workspace_id
                or approved.get("channel_id") != target.channel_id
                or approved.get("usergroup_ids") != list(target.usergroup_ids)
                or approved.get("link") != rendered.get("link")):
            raise DeliveryError("Slack destination differs from approved warning envelope", permanent=True)
        text = rendered.get("text")
        if not isinstance(text, str) or not rendered.get("expiry_utc", "").endswith(" UTC"):
            raise DeliveryError("rendered Slack warning is invalid", permanent=True)
        if target.usergroup_ids:
            text = " ".join(f"<!subteam^{group}>" for group in target.usergroup_ids) + " " + text
        token = payload.get("action_token")
        if not isinstance(token, str) or not token:
            raise DeliveryError("Slack acknowledgement action is unavailable", permanent=True)
        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": text}},
            {"type": "actions", "elements": [{"type": "button", "action_id": "uvm_warning_ack",
                "text": {"type": "plain_text", "text": "Acknowledge receipt"},
                "value": token, "style": "primary"}]}]
        blocks[0]["text"]["text"] += " <" + html.escape(rendered["link"], quote=True) + "|Open UVM>"
        # User-group identifiers are allowlisted Slack protocol tokens above;
        # escaping the complete fallback string would disable Slack mentions.
        body = json.dumps({"channel": target.channel_id, "text": text,
            "blocks": blocks, "unfurl_links": False, "unfurl_media": False},
            separators=(",", ":")).encode()
        request = urllib.request.Request(target.endpoint, data=body, method="POST", headers={
            "Content-Type": "application/json", "Authorization": "Bearer " + secret,
            "Idempotency-Key": payload["intent_id"]})
        try:
            opener = urllib.request.build_opener(_NoRedirect())
            with opener.open(request, timeout=8) as response:
                response_body = json.loads(response.read(64 * 1024))
                if response_body.get("ok") is False:
                    raise DeliveryError("Slack rejected the configured destination", permanent=True)
                if (response.status < 200 or response.status >= 300 or response_body.get("ok") is not True
                        or response_body.get("channel") != target.channel_id
                        or not isinstance(response_body.get("ts"), str)):
                    raise DeliveryUncertain("Slack returned an incomplete acceptance response")
                return "slack_api_accepted|" + response_body["channel"] + "|" + response_body["ts"]
        except urllib.error.HTTPError as exc:
            retry = exc.headers.get("Retry-After") if exc.headers else None
            if exc.code == 429:
                raise DeliveryError("Slack rate limit", retry_after_seconds=_bounded_retry(retry)) from None
            if 400 <= exc.code < 500 and exc.code != 408:
                raise DeliveryError(f"Slack rejected request with HTTP {exc.code}", permanent=True) from None
            raise DeliveryUncertain(f"Slack request outcome uncertain after HTTP {exc.code}") from None
        except (TimeoutError, OSError, urllib.error.URLError) as exc:
            reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            # OSError's canonical errno description contains no request, token,
            # URL userinfo or response bytes. Never persist arbitrary peer text.
            message = (os.strerror(reason.errno) if isinstance(reason, OSError)
                and isinstance(reason.errno, int) else "transport failure")
            endpoint = urllib.parse.urlsplit(target.endpoint)
            port = endpoint.port or (443 if endpoint.scheme == "https" else 80)
            raise DeliveryUncertain(
                f"transport outcome uncertain ({type(exc).__name__}; "
                f"reason={type(reason).__name__}: {message}; "
                f"endpoint={endpoint.hostname}:{port})") from None

    @staticmethod
    def _send_email(target: Destination, secret: str, payload: dict) -> str:
        message = EmailMessage()
        message["From"] = target.sender
        message["To"] = target.recipient
        rendered = payload["rendered"]
        message["Subject"] = rendered["subject"]
        message["Message-ID"] = f"<{payload['intent_id']}@uvm.local>"
        message.set_content(rendered["text"] + "\n")
        message.add_alternative(rendered["html"], subtype="html")
        client = None
        stage = "connect"
        try:
            if target.smtp_tls == "implicit":
                client = smtplib.SMTP_SSL(target.smtp_host, target.smtp_port, timeout=8,
                    context=ssl.create_default_context())
            else:
                client = smtplib.SMTP(target.smtp_host, target.smtp_port, timeout=8)
                stage = "greeting"
                client.ehlo()
                stage = "tls"
                client.starttls(context=ssl.create_default_context())
                client.ehlo()
            if secret:
                stage = "login"
                client.login(target.smtp_user, secret)
            stage = "mail"
            code, _ = client.mail(target.sender)
            if code >= 400:
                raise DeliveryError("SMTP sender rejected", permanent=code >= 500)
            stage = "rcpt"
            code, _ = client.rcpt(target.recipient)
            if code >= 400:
                raise DeliveryError("SMTP recipient rejected", permanent=code >= 500)
            # Once DATA is invoked, an exception may mean the server accepted
            # the message but its final response was lost. Earlier failures
            # cannot have submitted message bytes and remain retryable.
            stage = "data"
            code, _ = client.data(message.as_bytes(policy=SMTP))
            if code < 200 or code >= 300:
                raise DeliveryError("SMTP DATA rejected", permanent=code >= 500)
            message_id = message["Message-ID"]
            try:
                client.quit()
            except Exception:
                # DATA's final 2xx is the durable submission boundary.
                pass
            return "smtp_accepted|" + target.recipient + "|" + str(message_id)
        except DeliveryError:
            raise
        except smtplib.SMTPResponseException as exc:
            if exc.smtp_code >= 500:
                raise DeliveryError("SMTP permanently rejected submission", permanent=True) from None
            raise DeliveryError("SMTP temporarily rejected submission") from None
        except Exception as exc:
            if stage != "data":
                raise DeliveryError(f"SMTP {stage} failed before DATA ({type(exc).__name__})") from None
            raise DeliveryUncertain(f"SMTP outcome uncertain ({type(exc).__name__})") from None
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def _bounded_retry(value):
    try:
        return max(1, min(int(value), 3600))
    except (TypeError, ValueError):
        return 60


class FixtureAdapter:
    """In-process local proof adapter; it never opens a socket."""
    def __init__(self, outcomes: dict[str, list[str]] | None = None):
        self.outcomes = outcomes or {}
        self.receipts: list[tuple[str, str]] = []

    def send(self, *, channel: str, destination_ref: str, payload: dict) -> str:
        if not destination_ref.startswith("fixture:"):
            raise DeliveryError("local fixture adapter only accepts fixture destinations")
        plan = self.outcomes.get(destination_ref, [])
        outcome = plan.pop(0) if plan else "sent"
        if outcome == "interrupt":
            marker = os.environ.get("UVM_EXCEPTION_WARNING_FIXTURE_MARKER")
            if not marker:
                raise DeliveryError("fixture interruption marker is unavailable")
            with open(marker, "w", encoding="utf-8") as stream:
                stream.write(payload["intent_id"])
            while True:
                time.sleep(0.1)
        if outcome == "failed":
            raise DeliveryError("fixture rejected delivery")
        if outcome == "uncertain":
            raise DeliveryUncertain("fixture accepted request but lost its response")
        receipt = f"local-fixture:{channel}:{uuid.uuid4()}"
        self.receipts.append((payload["intent_id"], receipt))
        return receipt


def adapter_for(intent, fixture_adapter: Adapter | None = None) -> Adapter:
    if intent["destination_ref"].startswith("fixture:"):
        if fixture_adapter is None:
            raise DeliveryError("fixture adapter is unavailable")
        return fixture_adapter
    return HttpAdapter.from_environment()
