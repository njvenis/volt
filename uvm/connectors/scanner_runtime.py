"""Backend-owned, transaction-bound authority and credential bridge for scanners."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
import json
import re
import uuid

import sqlalchemy as sa
from uvm.assessment.command_occupancy import guard_command
from uvm.connectors.local_recovery import recovery_view, assert_profile_state, require_recovery_lease, invalidate_workflow

from uvm.assessment.policy_lock import lock_policy
from uvm.auth.local import COOKIE_NAME, LocalAuth
from uvm.auth.schema import AUTHORITY_CONTEXT
from uvm.connectors.api import _fail, _require, _revisions, _uuid
from uvm.connectors.crypto import decrypt, SecretUnavailable
from uvm.persistence.assessment_schema import (assessment_audit_events, assessment_command_receipts,
    assessment_command_abandonments, assessment_policy)
from uvm.persistence.connector_binding_schema import connector_bindings
from uvm.persistence.connector_schema import (connectors, connector_intents,
    connector_receipts, connector_secret_heads, connector_secrets)
from uvm.scanners import contracts as dto

UTC = timezone.utc
_NO_RESTORE = "00000000-0000-0000-0000-000000000000"
_RESULTS = {
    "scanner.configuration.save": (dto.SaveConfigurationResult, dto.SaveConfigurationReceipt),
    "scanner.connection.test": (dto.TestConnectionResult, dto.TestConnectionReceipt),
    "scanner.configuration.activate": (dto.ActivateConfigurationResult, dto.ActivateConfigurationReceipt),
    "scanner.collection.start": (dto.CollectResult, dto.CollectReceipt),
    "scanner.configuration.disable": (dto.DisableConfigurationResult, dto.DisableConfigurationReceipt),
}


def _instant(now):
    return now.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _snapshot(value):
    return dto.ScannerBindingSnapshot(**{**value,
        "expected_revisions": dto.ExpectedRevisions(**value["expected_revisions"])})


def _receipt(value):
    result_type, receipt_type = _RESULTS[value["action"]]
    return receipt_type(**{**value, "intents": tuple(value["intents"]), "result": result_type(**value["result"])})


def parse_qualys_credential(raw: bytes):
    """Validate secret content privately; callers never include it in errors."""
    try:
        value = json.loads(raw)
        if (not isinstance(value, dict) or set(value) != {"username", "password"}
                or not isinstance(value["username"], str) or not isinstance(value["password"], str)):
            raise ValueError
        return dto.QualysBasicCredential(value["username"], value["password"].encode("utf-8"))
    except (ValueError, TypeError, UnicodeError):
        _fail(400, "invalid_request", "Qualys credential must contain a valid username and password")


class SharedScannerRuntime:
    def __init__(self, app):
        self.app = app

    @contextmanager
    def transaction(self, *, request, action, connector_id, source_id,
                    expected_revisions=None, snapshot=None):
        try:
            grant = dto.required_scanner_grant(action)
        except ValueError:
            _fail(403, "forbidden", "Scanner action is not supported")
        _uuid(connector_id, "connector_id"); _uuid(source_id, "source_id")
        service = getattr(self.app.state, "oidc_auth", None)
        if not isinstance(service, LocalAuth):
            _fail(403, "forbidden", "Local scanner authority is required")
        write = action in _RESULTS
        if request.headers.get("authorization"):
            _fail(401, "authentication_required", "Authentication required")
        if write and (request.headers.get("origin") != service.config["public_origin"]
                or not request.headers.get("x-csrf-token")):
            _fail(403, "csrf_failed", "Request verification failed")
        handle = None
        token = None
        try:
            with self.app.state.engine.begin() as c:
                lock_policy(c)
                policy = c.execute(sa.select(assessment_policy).where(
                    assessment_policy.c.policy_id == 1).with_for_update()).mappings().first()
                context = service.resolve_cookie(c, request.cookies.get(COOKIE_NAME),
                    csrf_token=request.headers.get("x-csrf-token") if write else None)
                token = AUTHORITY_CONTEXT.set(context)
                if policy is None:
                    _fail(503, "dependency_unavailable", "Scanner authority is unavailable")
                row = c.execute(sa.select(connectors).where(
                    connectors.c.connector_id == connector_id).with_for_update()).mappings().first()
                registration = c.execute(sa.select(connector_bindings).where(
                    connector_bindings.c.connector_id == connector_id).with_for_update()).mappings().first()
                if row is None or registration is None or not registration["registration"]:
                    _fail(404, "not_found", "Scanner does not exist")
                if row["source_id"] != source_id or row["source_family"] != "qualys":
                    _fail(403, "source_scope_forbidden", "Source scope does not match")
                _require(policy["document"], context.principal_id, grant, row)
                assert_profile_state(c,row)
                if (action=='scanner.configuration.save' and expected_revisions is not None
                        and row['recovery'].get('state')!='clear'):
                    _fail(409,'restore_quarantined','Finish recovery before editing scanner configuration')
                handle = _ScannerTransaction(self, c, action, row, registration, policy, context,
                    expected_revisions, snapshot)
                if expected_revisions is not None and expected_revisions != handle.snapshot.expected_revisions:
                    _fail(409, "revision_conflict", "Scanner state changed")
                if snapshot is not None and snapshot != handle.snapshot:
                    _fail(409, "revision_conflict", "Scanner authority or retained state changed")
                yield handle
                handle._check_live()
        finally:
            if handle is not None:
                handle._active = False
            if token is not None:
                AUTHORITY_CONTEXT.reset(token)

    def authorize(self, *, request, action, connector_id, source_id, expected_revisions=None):
        with self.transaction(request=request, action=action, connector_id=connector_id,
                source_id=source_id, expected_revisions=expected_revisions) as tx:
            return tx.snapshot

    def assert_current(self, *, request, action, snapshot):
        with self.transaction(request=request, action=action, connector_id=snapshot.connector_id,
                source_id=snapshot.source_id, snapshot=snapshot):
            pass

    def read_registration_metadata(self, *, transaction):
        if not isinstance(transaction, _ScannerTransaction) or transaction._owner is not self:
            raise RuntimeError("foreign scanner transaction")
        transaction._check_live()
        return transaction._metadata()

    @contextmanager
    def credential_attempt(self, *, request, action, snapshot):
        action_name = {"test": "scanner.connection.test", "collect": "scanner.collection.start"}.get(action)
        if action_name is None:
            _fail(403, "forbidden", "Credential purpose is not supported")
        lease = None
        try:
            with self.transaction(request=request, action=action_name,
                    connector_id=snapshot.connector_id, source_id=snapshot.source_id, snapshot=snapshot) as tx:
                secret = tx._secret
                if (snapshot.credential_version_id is None or secret is None
                        or secret["purpose"] != "qualys_vm_basic" or secret["state"] != "active"
                        or secret["quarantine"] != "clear"):
                    _fail(409, "credential_revoked", "Scanner credential is unavailable")
                if tx._row['recovery'].get('state')!='clear':
                    if action!='test':
                        _fail(409,'restore_quarantined','Scanner is quarantined after restore')
                    require_recovery_lease(tx.connection,tx._row,secret)
                try:
                    plaintext = decrypt(secret, snapshot.connector_id,
                        snapshot.credential_slot_id, snapshot.credential_version_id)
                    lease = parse_qualys_credential(plaintext)
                    del plaintext
                except SecretUnavailable:
                    _fail(409, "credential_revoked", "Scanner credential is unavailable")
            # The transaction and policy lock are released before HTTP can use
            # the lease. Final publication takes its own fresh fenced transaction.
            yield lease
        finally:
            if lease is not None:
                lease.close()


class _ScannerTransaction:
    def __init__(self, owner, connection, action, row, registration, policy, context, expected, retained):
        self._owner, self._connection, self._action = owner, connection, action
        self._row, self._registration, self._policy, self._context = dict(row), dict(registration), policy, context
        self._expected, self._retained, self._active = expected, retained, True
        data = registration["registration"]
        if data.get("product") != "qualys_vm":
            _fail(404, "not_found", "Scanner does not exist")
        self._slot = data["credential_slots"]["qualys_vm_basic"]["secret_id"]
        head = connection.execute(sa.select(connector_secret_heads).where(
            connector_secret_heads.c.connector_id == row["connector_id"],
            connector_secret_heads.c.secret_id == self._slot).with_for_update()).mappings().first()
        if head is None or head["purpose"] != "qualys_vm_basic":
            _fail(409, "credential_revoked", "Scanner credential slot is unavailable")
        self._head_revision = int(head["revision"])
        self._secret = connection.execute(sa.select(connector_secrets).where(
            connector_secrets.c.connector_id == row["connector_id"],
            connector_secrets.c.secret_id == self._slot).order_by(
            sa.case((connector_secrets.c.state == "active", 0), else_=1),
            connector_secrets.c.created_at.desc(), connector_secrets.c.version_id.desc()).with_for_update()).mappings().first()
        if self._secret is not None and self._secret["purpose"] != "qualys_vm_basic":
            _fail(409, "credential_revoked", "Scanner credential purpose changed")

    def _check_live(self):
        if not self._active or self._connection.closed or not self._connection.in_transaction():
            raise RuntimeError("scanner transaction is no longer active")

    @property
    def connection(self):
        self._check_live()
        return self._connection

    @property
    def snapshot(self):
        self._check_live()
        row = self._row
        return dto.ScannerBindingSnapshot(self._context.principal_id, row["connector_id"], row["source_id"],
            row["source_family"], row["source_account_id"], row["scope_key"], row["configuration_revision"],
            row["connector_revision"], self._slot, self._secret["version_id"] if self._secret else None,
            row["recovery"].get("recovery_epoch_id") or _NO_RESTORE,
            dto.ExpectedRevisions(**_revisions(row, self._policy, self._context, None)),
            row["lifecycle"], row["active_configuration_revision"])

    def _metadata(self):
        value, row = self._registration["registration"], self._row
        secret = self._secret
        state = ("unconfigured" if secret is None else "quarantined" if
            secret["quarantine"] != "clear" else secret["state"])
        return dto.ScannerRegistrationMetadata(row["connector_id"], row["source_id"],
            dto.SourceTupleView(row["source_family"], row["source_account_id"], row["scope_key"]),
            self._registration["display_name"], value["account_label"], row["environment_label"],
            "qualys_vm", value["platform_id"], dto.ScannerScopeView("account_visible"),
            row["lifecycle"], row["configuration_revision"], row["active_configuration_revision"],
            dto.CredentialView(self._slot, secret["version_id"] if secret else None, state, self._head_revision),
            recovery_view(self.connection,row,secret))

    def _intent_row(self, command_id):
        return self.connection.execute(sa.select(connector_intents).where(
            connector_intents.c.kind == "scanner.command",
            connector_intents.c.payload["command_id"].as_string() == command_id).with_for_update()).mappings().first()

    def read_command(self, *, command_id, request_digest):
        _uuid(command_id, "command_id")
        if not isinstance(request_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", request_digest):
            _fail(400, "invalid_request", "Request digest is invalid")
        current = self.snapshot
        guard_command(self.connection, command_id, family='scanner',
            principal_id=current.principal_id, action=self._action,
            request_digest=request_digest, connector_id=current.connector_id,
            source_id=current.source_id, allow_terminal=True)
        row = self._intent_row(command_id)
        prior = self.connection.execute(sa.select(connector_receipts).where(
            connector_receipts.c.command_id == command_id).with_for_update()).mappings().first()
        used = self.connection.execute(sa.select(assessment_command_receipts.c.command_id).where(
            assessment_command_receipts.c.command_id == command_id).with_for_update()).first()
        terminal = self.connection.execute(sa.select(assessment_command_abandonments).where(
            assessment_command_abandonments.c.command_id == command_id).with_for_update()).mappings().first()
        current = self.snapshot
        if terminal is not None:
            if row is not None or prior is not None or used is not None:
                _fail(503, "inconsistent_operation", "Command disposition is inconsistent")
            if (terminal["principal_id"] != current.principal_id or terminal["action"] != self._action
                    or terminal["request_digest"] != request_digest):
                _fail(409, "command_conflict", "Command ID is bound to different content")
            event = self.connection.execute(sa.select(assessment_audit_events).where(
                assessment_audit_events.c.event_id == terminal["audit_event_id"])).mappings().first()
            after = event["after_value"] if event else None
            if (event is None or not isinstance(after, dict) or event["origin"] != "scanner_api"
                    or event["command_id"] != command_id or event["actor_id"] != terminal["principal_id"]
                    or event["action"] != terminal["action"] or after.get("stage") != "abandoned"
                    or after.get("disposition") != "not_committed"
                    or after.get("request_digest") != request_digest):
                _fail(503, "inconsistent_operation", "Command disposition audit is inconsistent")
            if event["target_id"] != current.connector_id or after.get("source_id") != current.source_id:
                _fail(409, "command_conflict", "Command ID is bound to a different source")
            return dto.ScannerCommandAbandonment(command_id, current.principal_id, self._action,
                request_digest, terminal["audit_event_id"], _instant(terminal["created_at"]))
        if row is None:
            if prior is not None or used is not None:
                _fail(409, "command_conflict", "Command ID is already bound")
            return None
        if used is not None:
            _fail(503, "inconsistent_operation", "Command admission is inconsistent")
        value = row["payload"]
        if (row["connector_id"] != current.connector_id or row["actor_id"] != current.principal_id
                or value["source_id"] != current.source_id or value["action"] != self._action
                or value["request_digest"] != request_digest):
            _fail(409, "command_conflict", "Command ID is bound to different content")
        intent = dto.ScannerCommandIntent(**{**value["intent"], "snapshot": _snapshot(value["intent"]["snapshot"])})
        if prior is not None and (prior["connector_id"] != current.connector_id
                or prior["actor_id"] != current.principal_id or prior["action"] != self._action
                or prior["request_digest"] != request_digest):
            _fail(409, "command_conflict", "Command receipt binding changed")
        return dto.ScannerCommandState(intent, _receipt(prior["receipt"]) if prior else None)

    def record_audited_abandonment(self, *, command_id, request_digest, rationale, evidence_ref):
        if self._action not in _RESULTS or self._expected is not None or self._retained is not None:
            _fail(409, "command_conflict", "Disposition requires current authority without admission fences")
        if any(not isinstance(value, str) or not value.strip() or len(value) > 2048
                for value in (rationale, evidence_ref)):
            _fail(400, "invalid_request", "Disposition audit evidence is required")
        state = self.read_command(command_id=command_id, request_digest=request_digest)
        if isinstance(state, dto.ScannerCommandAbandonment):
            return state
        if state is not None:
            _fail(409, "command_conflict", "Command already has retained admission or receipt")
        event_id, now = self._audit(command_id, "abandoned", rationale, evidence_ref, {}, {
            "source_id": self._row["source_id"], "request_digest": request_digest,
            "disposition": "not_committed"})
        self.connection.execute(assessment_command_abandonments.insert().values(
            command_id=command_id, principal_id=self._context.principal_id, action=self._action,
            request_digest=request_digest, audit_event_id=event_id, created_at=now))
        return dto.ScannerCommandAbandonment(command_id, self._context.principal_id,
            self._action, request_digest, event_id, _instant(now))

    def _audit(self, command_id, stage, rationale, evidence_ref, before, after):
        now = datetime.now(UTC)
        event_id = str(uuid.uuid4())
        seq = self.connection.execute(sa.select(sa.func.coalesce(sa.func.max(
            assessment_audit_events.c.event_sequence), 0) + 1)).scalar_one()
        self.connection.execute(assessment_audit_events.insert().values(event_id=event_id, event_sequence=seq,
            actor_id=self._context.principal_id, actor_kind="local_account", origin="scanner_api",
            action=self._action, target_id=self._row["connector_id"], before_value=before,
            after_value={"stage": stage, **after}, membership_ids=[], membership_revision=0,
            rationale=rationale, evidence_ref=evidence_ref, policy_revision=self._policy["revision"],
            identity_revision=0, occurred_at=now, received_at=now, correlation_id=command_id,
            command_id=command_id, authorization_context=self._context.document()))
        return event_id, now

    def record_audited_intent(self, *, command_id, request_digest, rationale, evidence_ref, operation_id, run_id):
        if self._action not in _RESULTS or self._expected is None:
            _fail(409, "revision_conflict", "A current command admission fence is required")
        if not isinstance(request_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", request_digest):
            _fail(400, "invalid_request", "Request digest is invalid")
        if any(not isinstance(v, str) or not v.strip() or len(v) > 1000 for v in (rationale, evidence_ref)):
            _fail(400, "invalid_request", "Audit evidence is required")
        if (self._action in {"scanner.connection.test", "scanner.collection.start"}) != (operation_id is not None):
            _fail(409, "revision_conflict", "Operation admission binding is invalid")
        if (self._action == "scanner.collection.start") != (run_id is not None):
            _fail(409, "revision_conflict", "Collection admission binding is invalid")
        if operation_id is not None: _uuid(operation_id, "operation_id")
        if run_id is not None: _uuid(run_id, "run_id")
        state = self.read_command(command_id=command_id, request_digest=request_digest)
        if isinstance(state, dto.ScannerCommandAbandonment):
            _fail(409, "command_terminal", "Command has a definitive noncommit disposition")
        if state is not None:
            _fail(409, "command_conflict", "Command already admitted")
        event_id, now = self._audit(command_id, "admitted", rationale, evidence_ref, {}, {"source_id": self._row["source_id"]})
        intent = dto.ScannerCommandIntent(str(uuid.uuid4()), command_id, self._row["connector_id"],
            self._row["source_id"], self._context.principal_id, self._action, request_digest,
            _instant(now), operation_id, run_id, self.snapshot)
        self.connection.execute(connector_intents.insert().values(intent_id=intent.intent_id,
            connector_id=intent.connector_id, kind="scanner.command", actor_id=intent.principal_id,
            status="pending", attempts=0, payload={"command_id": command_id, "source_id": intent.source_id,
                "action": self._action, "request_digest": request_digest, "rationale": rationale,
                "evidence_ref": evidence_ref, "admission_audit_event_id": event_id, "intent": asdict(intent)},
            result=None, created_at=now, updated_at=now))
        return intent

    def record_audited_receipt(self, *, intent_id, result, shared_state=None):
        _uuid(intent_id, "intent_id")
        row = self.connection.execute(sa.select(connector_intents).where(
            connector_intents.c.intent_id == intent_id).with_for_update()).mappings().first()
        if row is None or row["kind"] != "scanner.command":
            _fail(404, "not_found", "Scanner intent does not exist")
        value = row["payload"]
        state = self.read_command(command_id=value["command_id"], request_digest=value["request_digest"])
        intent = state.intent
        if type(result) is not _RESULTS.get(self._action, (None,))[0]:
            _fail(409, "revision_conflict", "Scanner result variant is invalid")
        if self._action in {"scanner.connection.test", "scanner.collection.start"}:
            permitted = {"succeeded", "failed", "interrupted"} | ({"partial"} if self._action == "scanner.collection.start" else set())
            if (result.status not in permitted or result.error_code is not None and
                    (not isinstance(result.error_code, str) or not re.fullmatch(r"[a-z0-9_]{1,64}", result.error_code))):
                _fail(409, "revision_conflict", "Scanner terminal result is invalid")
        if state.receipt is not None:
            if state.receipt.result != result:
                _fail(409, "command_conflict", "Scanner result already committed")
            return dto.ScannerCommandCommit(state.receipt, self.snapshot)
        if intent.operation_id is not None:
            if self._retained != intent.snapshot or getattr(result, "operation_id", None) != intent.operation_id:
                _fail(409, "revision_conflict", "Operation completion requires its retained fence")
            if getattr(result, "run_id", None) != intent.run_id:
                _fail(409, "revision_conflict", "Collection result binding changed")
        elif self._expected is None or self.snapshot != intent.snapshot:
            _fail(409, "revision_conflict", "Local command admission fence changed")
        before = asdict(self.snapshot)
        local_action = self._action in {"scanner.configuration.save", "scanner.configuration.activate", "scanner.configuration.disable"}
        if local_action != (shared_state is not None):
            _fail(409, "revision_conflict", "Scanner projection does not match its action")
        if shared_state is not None:
            old = self._row["configuration_revision"]
            wanted = {"scanner.configuration.save": ("staged", old + 1, None),
                "scanner.configuration.activate": ("active", old, old),
                "scanner.configuration.disable": ("disabled", old, None)}[self._action]
            if (type(shared_state) is not dto.ScannerSharedStateChange or
                    type(shared_state.configuration_revision) is not int
                    or (shared_state.active_configuration_revision is not None and type(shared_state.active_configuration_revision) is not int)
                    or type(result.configuration_revision) is not int
                    or (self._action == "scanner.configuration.activate" and old < 1)
                    or
                    (shared_state.lifecycle, shared_state.configuration_revision, shared_state.active_configuration_revision) != wanted
                    or result.lifecycle != shared_state.lifecycle or result.configuration_revision != shared_state.configuration_revision
                    or (self._action == "scanner.configuration.activate" and
                        result.active_configuration_revision != shared_state.active_configuration_revision)):
                _fail(409, "revision_conflict", "Scanner projection transition is invalid")
            recovery=self._row['recovery']
            if self._action=='scanner.configuration.activate' and recovery.get('state')!='clear':
                if self._secret is None:
                    _fail(409,'credential_revoked','Scanner credential is unavailable')
                record=require_recovery_lease(self.connection,self._row,self._secret,activation=True)
                recovery={**recovery,'state':'clear','requires_fresh_credentials':False,
                    'operator_clearance_present':True,'approval_id':record['approval_id'],'reason':None}
            elif self._action=='scanner.configuration.save':
                recovery=invalidate_workflow(self.connection,self._row)
            updates = {**asdict(shared_state), "recovery":recovery,"connector_revision": self._row["connector_revision"] + 1,
                "updated_at": datetime.now(UTC)}
            self.connection.execute(connectors.update().where(connectors.c.connector_id == self._row["connector_id"]).values(**updates))
            self._row.update(updates)
        event_id, now = self._audit(intent.command_id, "committed", value["rationale"], value["evidence_ref"], before,
            {"source_id": intent.source_id, "result": asdict(result)})
        receipt_type = _RESULTS[self._action][1]
        receipt = receipt_type(schema_version=1, command_id=intent.command_id, decision_id=str(uuid.uuid4()),
            audit_event_id=event_id, intent_id=intent_id, committed_revision=self._row["connector_revision"],
            projection={"status": "committed", "connector_id": intent.connector_id, "source_id": intent.source_id,
                "expected_revisions": asdict(self.snapshot.expected_revisions)}, action=self._action,
            target_id=intent.connector_id, policy_revision=self._policy["revision"], intents=({"intent_id": intent_id,
                "kind": "scanner.command", "target_id": intent.connector_id, "status": "complete"},),
            occurred_at=_instant(now), result=result)
        self.connection.execute(connector_receipts.insert().values(connector_id=intent.connector_id,
            command_id=intent.command_id, actor_id=intent.principal_id, action=intent.action,
            request_digest=intent.request_digest, receipt=asdict(receipt), created_at=now))
        self.connection.execute(connector_intents.update().where(connector_intents.c.intent_id == intent_id).values(
            status="complete", result={"command_id": intent.command_id, "audit_event_id": event_id}, updated_at=now))
        return dto.ScannerCommandCommit(receipt, self.snapshot)
