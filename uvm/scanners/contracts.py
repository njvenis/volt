"""Proposed shared-service boundary and scanner API DTO checkpoint.

The backend owns the adapter implementation. This module defines no auth
policy, no permission evaluator and no credential cryptography.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, ContextManager, Literal, Protocol

from sqlalchemy.engine import Connection


ScannerAction = Literal[
    "scanner.configuration.save", "scanner.connection.test",
    "scanner.configuration.activate", "scanner.collection.start",
    "scanner.configuration.disable",
]
ScannerReadAction = Literal["connector.read", "assessment.read"]
ScannerAuthorizationAction = ScannerAction | ScannerReadAction
SCANNER_GRANT_BY_ACTION: dict[str, str] = {
    "scanner.configuration.save": "connector.configure",
    "scanner.connection.test": "connector.configure",
    "scanner.configuration.activate": "connector.configure",
    "scanner.collection.start": "connector.configure",
    "scanner.configuration.disable": "connector.configure",
    "connector.read": "connector.read",
    "assessment.read": "assessment.read",
}


def required_scanner_grant(action: ScannerAuthorizationAction) -> str:
    """Fixed local permission mapping; action strings are never grant names."""
    try:
        return SCANNER_GRANT_BY_ACTION[action]
    except KeyError:
        raise ValueError("unsupported_scanner_action") from None


OperationKind = Literal["test", "collect"]
OperationStatus = Literal["running", "succeeded", "partial", "failed", "interrupted"]


@dataclass(frozen=True)
class ExpectedRevisions:
    target: int
    policy: int
    identity_membership: int
    owners: int
    authority: int
    connector: int
    source: int
    secret_source: int
    secret: int | None

    def __post_init__(self) -> None:
        values = (self.target, self.policy, self.identity_membership, self.owners,
            self.authority, self.connector, self.source, self.secret_source)
        if any(type(value) is not int or value < 0 for value in values):
            raise ValueError("revision values must be non-negative integers")
        if self.secret is not None and (type(self.secret) is not int or self.secret < 0):
            raise ValueError("secret revision must be null or a non-negative integer")

    def as_tuple(self) -> tuple[int | None, ...]:
        return (self.target, self.policy, self.identity_membership, self.owners,
            self.authority, self.connector, self.source, self.secret_source, self.secret)


@dataclass(frozen=True)
class ScannerBindingSnapshot:
    """Non-secret source and configuration snapshot returned by auth service."""
    principal_id: str
    connector_id: str
    source_id: str
    source_family: str
    source_account_id: str
    scope_key: str
    configuration_revision: int
    connector_revision: int
    credential_slot_id: str
    credential_version_id: str | None
    restore_epoch_id: str
    expected_revisions: ExpectedRevisions
    lifecycle: Literal["disabled", "staged", "active"]
    active_configuration_revision: int | None


class QualysBasicCredential:
    """One-attempt Basic credential lease; redacted and zeroed on scope exit."""
    __slots__ = ("_username", "_password", "_closed")

    def __init__(self, username: str, password: bytes | bytearray):
        if (not isinstance(username, str) or not username or ":" in username
                or any(ord(char) < 0x20 or ord(char) == 0x7f for char in username)
                or not isinstance(password, (bytes, bytearray)) or not password):
            raise ValueError("invalid Qualys Basic credential")
        self._username = username
        self._password = bytearray(password)
        self._closed = False

    def __enter__(self) -> "QualysBasicCredential":
        if self._closed:
            raise RuntimeError("credential lease is closed")
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def authorization_header(self) -> str:
        if self._closed:
            raise RuntimeError("credential lease is closed")
        raw = self._username.encode("utf-8") + b":" + bytes(self._password)
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def close(self) -> None:
        for index in range(len(self._password)):
            self._password[index] = 0
        self._closed = True

    def __repr__(self) -> str:
        return "QualysBasicCredential(<redacted>)"

    __str__ = __repr__


class ScannerRuntimeAdapters(Protocol):
    """Narrow adapter service proposed for shared backend implementation.

    Every call is request-bound and re-evaluates the current local-session
    context and grant against the exact connector/source tuple. It must not
    derive source identity from labels or re-use stale request authority.
    """
    def transaction(self, *, request: object, action: ScannerAuthorizationAction,
                    connector_id: str, source_id: str,
                    expected_revisions: ExpectedRevisions | None = None,
                    snapshot: ScannerBindingSnapshot | None = None
                    ) -> ContextManager[ScannerTransaction]:
        """Own one short DB transaction and shared policy/connector lock.

        Validate writes through existing shared Origin/CSRF/local-session services;
        refresh the session and exact-source grant inside the lock. If supplied,
        compare the complete revision vector and/or operation snapshot including
        credential slot/version, restore epoch, configuration and lifecycle.
        Yield the SAME connection for provider writes and shared audit/intent/
        receipt writes. Normal exit commits once; any exception rolls back all.
        No network, credential lease, evidence I/O or independent repository
        commit is permitted inside this context. A yielded object is valid only
        until exit. Backend owns lock acquisition order and implementation.
        """
        ...

    def read_registration_metadata(self, *, transaction: ScannerTransaction
                                   ) -> ScannerRegistrationMetadata:
        """Read only this live transaction's authorized registered binding.

        Reject expired/foreign transaction handles. Source identity, platform,
        product and scope are immutable registration values; labels confer no
        authority. Lifecycle/revisions/credential state are current locked reads.
        """
        ...

    def authorize(self, *, request: object, action: ScannerAuthorizationAction,
                  connector_id: str, source_id: str,
                  expected_revisions: ExpectedRevisions | None = None
                  ) -> ScannerBindingSnapshot:
        """Authorize the exact source tuple under the shared policy lock.

        Exact authorization identity is source_family/source_account_id/scope_key
        paired with connector_id/source_id from the current stored registration;
        labels are never keys. The returned snapshot is a fence token, not a
        bearer grant.
        """
        ...

    def credential_attempt(self, *, request: object, action: OperationKind,
                  snapshot: ScannerBindingSnapshot
                  ) -> ContextManager[QualysBasicCredential]:
        """Yield one request-attempt lease, then zero mutable password bytes.

        Reject a snapshot with credential_version_id=None or an inactive or
        revoked slot before entering this lease.

        Backend implementation must re-read and enforce purpose exactly
        ``qualys_vm_basic``, connector/source/allocated credential-slot/version
        association, active version state and restore quarantine under the
        backend policy lock. It then calls existing connector crypto and releases
        its DB transaction/policy lock BEFORE yielding the lease for HTTP. It must
        never return ciphertext or a long-lived credential object. The lease
        repr/str is redacted; callers may derive Basic Authorization only
        inside the context and must remove the header from request objects on
        exit.
        """
        ...

    def assert_current(self, *, request: object, action: ScannerAuthorizationAction,
                  snapshot: ScannerBindingSnapshot) -> None:
        """Refresh session and recheck grant/revisions/restore epoch.

        Call immediately before each provider HTTP attempt. This standalone
        check is not an atomic publication fence: publication and reads use
        transaction(snapshot=...) instead. A stale snapshot must fail closed.
        """
        ...


@dataclass(frozen=True)
class CredentialView:
    secret_id: str
    version_id: str | None
    state: Literal["unconfigured", "inactive", "active", "revoked", "quarantined"]
    revision: int

    def __post_init__(self) -> None:
        if type(self.revision) is not int or self.revision < 0:
            raise ValueError("credential revision must be a non-negative integer")


@dataclass(frozen=True)
class ValidationView:
    status: Literal["unverified", "succeeded", "failed"]
    checked_at: str | None
    configuration_revision: int | None
    credential_version_id: str | None
    operation_id: str | None
    error_code: str | None


@dataclass(frozen=True)
class ScannerLimitsView:
    max_pages: int = 10
    max_page_bytes: int = 10 * 1024 * 1024
    max_operation_bytes: int = 50 * 1024 * 1024
    max_detections: int = 100_000
    overall_deadline_seconds: int = 120
    request_timeout_seconds: int = 30
    max_attempts_per_page: int = 3


@dataclass(frozen=True)
class CollectionRecencyView:
    status: Literal["never", "recent", "stale"]
    as_of: str
    last_complete_at: str | None


@dataclass(frozen=True)
class SourceTupleView:
    source_family: Literal["qualys"]
    source_account_id: str
    scope_key: str


@dataclass(frozen=True)
class ScannerScopeView:
    kind: Literal["account_visible"]


@dataclass(frozen=True)
class RecoveryView:
    """Safe current backend recovery metadata, never proof or lease authority.

    All values are required from the current authorized metadata read. Initial
    clear/null/false values describe verified initial state, never a fallback
    for absent configuration or missing recovery state.
    """
    state: Literal["clear", "quarantined", "awaiting_activation"]
    epoch_id: str | None
    fresh_credentials_required: bool
    fresh_version_ready: bool
    clearance_state: Literal["missing", "available", "applied", "expired", "invalidated"]
    approval_id: str | None
    approval_expires_at: str | None


@dataclass(frozen=True)
class ScannerView:
    schema_version: Literal[1]
    connector_id: str
    source_id: str
    source_tuple: SourceTupleView
    display_name: str
    account_label: str
    environment_label: str
    product: Literal["qualys_vm"]
    platform_id: str
    scope: ScannerScopeView
    lifecycle: Literal["disabled", "staged", "active"]
    configuration_revision: int
    active_configuration_revision: int | None
    credential: CredentialView
    expected_revisions: ExpectedRevisions
    validation: ValidationView | None
    limits: ScannerLimitsView
    collection_mode: Literal["manual"]
    schedule_supported: Literal[False]
    latest_attempt_run_id: str | None
    latest_complete_run_id: str | None
    collection_recency: CollectionRecencyView
    recovery: RecoveryView


@dataclass(frozen=True)
class OperationView:
    schema_version: Literal[1]
    operation_id: str
    command_id: str
    kind: OperationKind
    status: OperationStatus
    configuration_revision: int
    credential_version_id: str | None
    started_at: str
    finished_at: str | None
    run_id: str | None
    error_code: str | None
    receipt_id: str | None


@dataclass(frozen=True)
class DetectionView:
    observation_id: str
    group_id: str | None
    qid: str
    host_id: str | None
    detection_type: str | None
    severity: str | None
    vendor_status: str | None
    port: str | None
    protocol: str | None
    ssl: str | None
    unique_vuln_id: str | None
    vendor_timestamps: dict[str, str]
    collected_at: str
    observed_at: str | None
    identity_resolution: str
    evidence_ref: str
    evidence_sha256: str


@dataclass(frozen=True)
class RetrievalView:
    status: Literal["complete", "partial", "failed"]
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class CoverageView:
    status: Literal["unknown"]
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class SourceFreshnessView:
    status: Literal["unknown"]
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class DetectionPage:
    schema_version: Literal[1]
    run_id: str
    as_of: str
    items: tuple[DetectionView, ...]
    next_cursor: str | None
    retrieval: RetrievalView
    coverage: CoverageView
    source_freshness: SourceFreshnessView
    collection_recency: CollectionRecencyView


@dataclass(frozen=True)
class SaveConfigurationResult:
    lifecycle: Literal["disabled", "staged", "active"]
    configuration_revision: int


@dataclass(frozen=True)
class TestConnectionResult:
    operation_id: str
    status: Literal["succeeded", "failed", "interrupted"]
    error_code: str | None


@dataclass(frozen=True)
class ActivateConfigurationResult:
    lifecycle: Literal["active"]
    configuration_revision: int
    active_configuration_revision: int


@dataclass(frozen=True)
class CollectResult:
    operation_id: str
    run_id: str
    status: Literal["succeeded", "partial", "failed", "interrupted"]
    error_code: str | None


@dataclass(frozen=True)
class DisableConfigurationResult:
    lifecycle: Literal["disabled"]
    configuration_revision: int


@dataclass(frozen=True)
class _ReceiptBase:
    schema_version: Literal[1]
    command_id: str
    decision_id: str
    audit_event_id: str
    intent_id: str
    committed_revision: int
    projection: dict[str, Any]
    action: ScannerAction
    target_id: str
    policy_revision: int
    intents: tuple[dict[str, Any], ...]
    occurred_at: str


@dataclass(frozen=True)
class SaveConfigurationReceipt(_ReceiptBase):
    action: Literal["scanner.configuration.save"]
    result: SaveConfigurationResult


@dataclass(frozen=True)
class TestConnectionReceipt(_ReceiptBase):
    action: Literal["scanner.connection.test"]
    result: TestConnectionResult


@dataclass(frozen=True)
class ActivateConfigurationReceipt(_ReceiptBase):
    action: Literal["scanner.configuration.activate"]
    result: ActivateConfigurationResult


@dataclass(frozen=True)
class CollectReceipt(_ReceiptBase):
    action: Literal["scanner.collection.start"]
    result: CollectResult


@dataclass(frozen=True)
class DisableConfigurationReceipt(_ReceiptBase):
    action: Literal["scanner.configuration.disable"]
    result: DisableConfigurationResult


ScannerCommandReceipt = (SaveConfigurationReceipt | TestConnectionReceipt
    | ActivateConfigurationReceipt | CollectReceipt | DisableConfigurationReceipt)


# Shared transaction bridge adopted by root at 171285a; backend owns implementation.
ScannerCommandResult = (SaveConfigurationResult | TestConnectionResult
    | ActivateConfigurationResult | CollectResult | DisableConfigurationResult)


@dataclass(frozen=True)
class ScannerRegistrationMetadata:
    connector_id: str
    source_id: str
    source_tuple: SourceTupleView
    display_name: str
    account_label: str
    environment_label: str
    product: Literal["qualys_vm"]
    platform_id: str
    scope: ScannerScopeView
    lifecycle: Literal["disabled", "staged", "active"]
    configuration_revision: int
    active_configuration_revision: int | None
    credential: CredentialView
    recovery: RecoveryView


@dataclass(frozen=True)
class ScannerSharedStateChange:
    """Mechanical shared connector projection, never settings/secret material.

    save advances configuration_revision once, stages and clears active revision;
    activate selects the validated current revision; disable clears active revision.
    Backend advances connector revision once only when applying this change.
    Test/collect admission and completion pass None and do not advance revisions.
    """
    lifecycle: Literal["disabled", "staged", "active"]
    configuration_revision: int
    active_configuration_revision: int | None


@dataclass(frozen=True)
class ScannerCommandIntent:
    """Backend-owned durable reservation; IDs and actor are backend-generated."""
    intent_id: str
    command_id: str
    connector_id: str
    source_id: str
    principal_id: str
    action: ScannerAction
    request_digest: str
    occurred_at: str
    operation_id: str | None
    run_id: str | None
    snapshot: ScannerBindingSnapshot


@dataclass(frozen=True)
class ScannerCommandAbandonment:
    """Backend-owned audited terminal fact in the existing0065 shared ledger.

    A matching fact proves this exact actor/action/public-command digest cannot
    later admit. It contains no network operation, findings or credential bytes.
    Connector/source binding is included in that original command digest and is
    checked against the current authorized transaction before returning the fact.
    """
    command_id: str
    principal_id: str
    action: ScannerAction
    request_digest: str
    audit_event_id: str
    occurred_at: str


@dataclass(frozen=True)
class ScannerCommandState:
    intent: ScannerCommandIntent
    receipt: ScannerCommandReceipt | None


@dataclass(frozen=True)
class ScannerCommandCommit:
    receipt: ScannerCommandReceipt
    snapshot: ScannerBindingSnapshot


@dataclass(frozen=True)
class _ScannerDispositionBase:
    schema_version: Literal[1]
    command_id: str
    connector_id: str
    source_id: str
    action: ScannerAction
    actor_id: str
    request_digest: str


@dataclass(frozen=True)
class ScannerNotCommittedDisposition(_ScannerDispositionBase):
    disposition: Literal["not_committed"]
    audit_event_id: str
    occurred_at: str


@dataclass(frozen=True)
class ScannerCommittedDisposition(_ScannerDispositionBase):
    disposition: Literal["committed"]
    receipt: ScannerCommandReceipt


@dataclass(frozen=True)
class ScannerAdmittedDisposition(_ScannerDispositionBase):
    disposition: Literal["admitted"]
    operation: OperationView


ScannerCommandDisposition = (ScannerNotCommittedDisposition
    | ScannerCommittedDisposition | ScannerAdmittedDisposition)


class ScannerTransaction(Protocol):
    """Backend-owned live handle; not constructible from API request data.

    All methods below use connection, with no engine.begin(), independent commit,
    or nested transaction owner. Shared-table implementation remains backend-only.
    Provider calls its own connection-taking store functions on this connection.
    """
    @property
    def connection(self) -> Connection: ...

    @property
    def snapshot(self) -> ScannerBindingSnapshot: ...

    def read_command(self, *, command_id: str,
                     request_digest: str
                     ) -> ScannerCommandState | ScannerCommandAbandonment | None:
        """Current-authorized replay lookup, before new-command revision checks.

        Enforce current principal/action/connector/source/digest exact binding;
        changed actor/content conflicts. Never return another source's record.
        May use transaction without old expected revisions to read a replay.
        Check the existing0065 shared abandonment ledger in the same lookup;
        matching terminal facts return ScannerCommandAbandonment, changed
        principal/action/digest conflicts. A tombstone together with a retained
        admission/receipt is inconsistent, never definitive noncommit.
        Under adopted ee79830, None additionally means no occupancy in ANY
        shared command family (assessment/connector/scanner/pending secret).
        Foreign-family occupancy conflicts, never becomes a scanner result or
        noncommit proof; all shared writers/settlements must honor tombstones.
        """
        ...

    def record_audited_abandonment(self, *, command_id: str, request_digest: str,
                                    rationale: str, evidence_ref: str
                                    ) -> ScannerCommandAbandonment:
        """Audit and fence an unadmitted command using this SAME connection.

        Current session/CSRF/exact source authority uses the original scanner
        action; historical admission revisions are intentionally not evaluated.
        Derive actor/action/source from the live handle. Recheck no receipt or
        admitted intent or foreign-family/pending-secret occupancy exists under
        the shared policy/connector lock, then
        atomically append audit plus the existing0065 terminal ledger row. Do
        not synthesize operation admission or replace original stale fences.
        Exact matching replay returns the original fact without a new audit;
        changed actor/action/digest conflicts. Persistence/audit failure rolls
        back the tombstone. Result is not a commit proof until context exit and
        current-authorized durable readback. No HTTP or provider audit SQL.
        """
        ...

    def record_audited_intent(self, *, command_id: str, request_digest: str,
                              rationale: str, evidence_ref: str,
                              operation_id: str | None, run_id: str | None
                              ) -> ScannerCommandIntent:
        """Reserve novel command plus admission audit on this transaction.

        Require a write-action transaction with expected_revisions supplied.
        Bind actor/action/source from its current snapshot, not caller strings.
        Persist the full admitted snapshot in the existing intent payload and
        return it; finalization compares against that retained snapshot.
        Caller persists provider operation/config changes on connection before
        exit. Unique command conflict rolls back; re-read under current authority.
        Local commands create intent and receipt in the same transaction.
        """
        ...

    def record_audited_receipt(self, *, intent_id: str,
                               result: ScannerCommandResult,
                               shared_state: ScannerSharedStateChange | None = None
                               ) -> ScannerCommandCommit:
        """Finalize the retained intent and audit/receipt using this connection.

        Verify retained principal/action/source/request binding and exact result
        variant. An operation completion requires transaction(snapshot=admitted
        snapshot); a local command requires its admission revision fence. Apply
        only the typed shared connector projection, generate audit/decision IDs,
        and return the receipt plus resulting snapshot/revision vector. Receipt
        is immutable and exact replay returns it; conflicting finalization fails.
        Audit/intent/receipt failure rolls back provider writes in this context.
        This return precedes commit; caller returns success only after context
        exit and durable readback. Neither this method nor any lock scope makes
        separate observation/identity repository commits atomic with publication.
        """
        ...
