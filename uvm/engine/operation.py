"""Engine import operations (EngineImportOperationV1) and their store.

In-memory contract code for the DefectDojo CE import/reimport boundary
(CR-01/03/04). Pure stdlib, no HTTP, no persistence, no engine calls.
The contract follows
``openspec/changes/g1-engine-identity-contracts/design.md`` (the
``EngineImportOperationV1`` row of the Version 1 shared contracts table):

- one operation targets one intended context and one retained payload;
  the full pre-POST context (context key, source run, scan type, parser
  configuration, engine release, request kind) and the payload digest are
  recorded before any HTTP write;
- ``close_old_findings`` is always an explicit ``False`` on reimport;
- repeating the same operation ID/payload triggers reconciliation, never
  an automatic second POST; reusing the ID with different bytes or context
  is ``conflict``;
- writes are serialised per context and per Test bound by request, response
  or settlement: an active context rejects a second operation; a settled
  mapping fixes the Test for its later reimports, and a foreign context
  cannot claim that Test;
- HTTP acceptance creates ``pending``; a lost/uncertain response moves the
  operation to ``quarantined`` and blocks a second POST;
  a conflicting second HTTP response likewise quarantines the operation
  (retaining the first response evidence) and blocks settle until
  reconciliation. Reconciliation is a versioned verified supported-API event
  (``ReconciliationEventV1``: evidence ref plus scope) — a bare caller Boolean
  is never evidence; a first-import read that found zero candidates cannot
  prove that the issued POST has stopped or did not write; all lost-response
  retries stay blocked;
  if reconciliation's read-back discovers the write already completed, a
  unique context/Test/Finding candidate settles the quarantined operation
  without any new POST (``settle_reconciliation_readback``) from a versioned
  verified event (``ReconciliationReadbackV1``) — but only for a first
  import with a verified empty pre-POST context, where a single verified
  fresh candidate Test in the intended context is the write. A lost
  *reimport* response can never settle from a read-back: the CE supported
  API (3.3.100/3.3.200) supplies no independently verifiable write
  provenance or non-execution field, a caller-supplied source-run correlation is not
  supported-API proof, and stale preexisting Test/Finding data must never
  advance the revision — the reimport stays quarantined and unresolved;
- only completed deduplication plus a matching supported-API Test/Finding
  read-back can make the operation ``settled``; the read-back must be a
  complete verified event (``FindingReadbackV1``: evidence ref plus verified
  flag) covering the full measured Finding scope — a verified empty set is
  allowed, but unverified emptiness and naked caller-supplied Finding IDs
  are rejected; a definitive rejected request is ``failed``; a false/absent
  asynchronous deduplication flag advances to ``true`` only through an
  explicit verified read-back of an explicit ``True`` completion
  (``record_dedup_readback``), never through a second HTTP response or a
  ``False`` read-back; True completion is monotonic and can never be
  re-recorded as false;
- a pending or quarantined operation never advances or erases the prior
  active mapping; only a settled operation advances it.

CE 3.3.100 evidence: the async response may carry
``deduplication_complete=false`` (deduplication can be dispatched
asynchronously and ``async_wait`` can time out), and the HTTP outcome can
be uncertain. Both are modelled here: a false/absent completion flag and
an uncertain response leave the operation non-settled.

Engine Finding/endpoint counts are measured outputs of a settled
read-back only; they are never inferred as UVM occurrence counts and no
assessment or remediation is derived from them in this module.

Synthetic-fixture scope only: nothing here is durable persistence, live
API integration or external-system evidence.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Optional

SCHEMA_VERSION = 1

# Operation states (design: pending/settled/failed/quarantined/conflict).
STATUS_PENDING = "pending"
STATUS_SETTLED = "settled"
STATUS_FAILED = "failed"
STATUS_QUARANTINED = "quarantined"
STATUS_CONFLICT = "conflict"
_STATUSES = (
    STATUS_PENDING,
    STATUS_SETTLED,
    STATUS_FAILED,
    STATUS_QUARANTINED,
    STATUS_CONFLICT,
)

# A non-terminal state: it keeps the context's write serialised and blocks
# a second operation for that context until it settles, fails or is
# explicitly resolved through reconciliation.
_ACTIVE_STATUSES = (STATUS_PENDING, STATUS_QUARANTINED, STATUS_CONFLICT)

# Request kinds: first auto-create via /api/v2/import-scan/ vs recurring
# reimport via /api/v2/reimport-scan/ with the registered Test ID.
REQUEST_IMPORT = "import"
REQUEST_REIMPORT = "reimport"
_REQUEST_KINDS = (REQUEST_IMPORT, REQUEST_REIMPORT)


@dataclass(frozen=True)
class EngineImportOperationV1:
    """One engine import/reimport against one intended context and one
    retained payload. Immutable; every mutation returns a new revision."""

    # required
    schema_version: int
    operation_id: str  # stable UVM UUID (not assumed to be a DefectDojo key)
    revision: int
    context_key: str  # intended Product/Engagement/Test registration
    source_run_id: str
    scan_type: str
    payload_sha256: str
    parser_config_version: str
    engine_release: str
    request_kind: str  # REQUEST_IMPORT | REQUEST_REIMPORT
    requested_at: datetime
    close_old_findings: bool  # always explicitly False
    status: str
    # optional / conditional
    test_id: Optional[str] = None  # required for reimport; immutable request context
    bound_test_id: Optional[str] = None  # Test bound on settle; a result, never a request mutation
    response_deduplication_complete: Optional[bool] = None  # dedup flag as captured on the original response
    response_ref: Optional[str] = None
    response_test_id: Optional[str] = None
    deduplication_complete: Optional[bool] = None  # explicit 0/false/absent
    deduplication_evidence_ref: Optional[str] = None  # verified read-back evidence
    settle_readback_ref: Optional[str] = None  # complete read-back settle evidence
    reconciliation_evidence_ref: Optional[str] = None  # verified absence read-back
    first_import_baseline_ref: Optional[str] = None  # verified empty context before POST
    finding_ids: tuple = ()  # measured read-back outputs, not occurrence counts
    endpoint_ids: tuple = ()
    mapping_revision: Optional[int] = None
    prior_mapping_revision: Optional[int] = None  # retained while pending
    error_code: Optional[str] = None
    error_detail_ref: Optional[str] = None
    supersedes_operation_id: Optional[str] = None
    # transport bookkeeping (store-managed)
    post_issued: bool = False  # a POST has been issued for this payload
    reconciled: bool = False  # retained V1 field; no lost-response retry is authorised

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version!r}")
        try:
            uuid.UUID(self.operation_id)
        except (ValueError, AttributeError, TypeError):
            raise ValueError(
                f"operation_id must be a UUID, got {self.operation_id!r}"
            ) from None
        if self.revision < 1:
            raise ValueError("revision must be a positive integer")
        for name in (
            "context_key",
            "source_run_id",
            "scan_type",
            "payload_sha256",
            "parser_config_version",
            "engine_release",
        ):
            if not getattr(self, name):
                raise ValueError(f"{name} is required")
        if self.request_kind not in _REQUEST_KINDS:
            raise ValueError(
                f"request_kind must be one of {_REQUEST_KINDS}, "
                f"got {self.request_kind!r}"
            )
        if self.status not in _STATUSES:
            raise ValueError(
                f"status must be one of {_STATUSES}, got {self.status!r}"
            )
        if self.requested_at is None:
            raise ValueError("requested_at is required")
        if self.requested_at.tzinfo is None:
            raise ValueError("requested_at must be a timezone-aware UTC instant")
        if self.close_old_findings is not False:
            raise ValueError(
                "close_old_findings must be explicitly False; absence of "
                "legacy findings is not remediation and the tagged reimport "
                "serializer defaults it to True"
            )
        if self.request_kind == REQUEST_REIMPORT and not self.test_id:
            raise ValueError(
                "reimport requires the registered test_id; it is null only "
                "before the first auto-created Test is confirmed (import)"
            )
        if self.mapping_revision is not None and self.mapping_revision < 1:
            raise ValueError("mapping_revision must be a positive integer")
        if self.prior_mapping_revision is not None and self.prior_mapping_revision < 1:
            raise ValueError("prior_mapping_revision must be a positive integer")
        if self.deduplication_complete is not None and not isinstance(
            self.deduplication_complete, bool
        ):
            raise ValueError("deduplication_complete must be a bool or explicit null")
        if (
            self.response_deduplication_complete is not None
            and not isinstance(self.response_deduplication_complete, bool)
        ):
            raise ValueError(
                "response_deduplication_complete must be a bool or explicit null"
            )
        if self.status == STATUS_PENDING and not self.post_issued:
            # Pre-POST state: no recorded HTTP response evidence. Response
            # fields are set only by record_response, which requires the
            # POST to have been issued, so a pre-POST DTO carrying them is
            # evidence about a write that never happened.
            if self.response_ref is not None:
                raise ValueError(
                    "a pending operation must not carry response_ref; HTTP "
                    "response evidence is recorded only after issue_post"
                )
            if self.response_test_id is not None:
                raise ValueError(
                    "a pending operation must not carry response_test_id; it "
                    "is recorded only with the post-POST HTTP response"
                )
            if self.response_deduplication_complete is not None:
                raise ValueError(
                    "a pending operation must not carry "
                    "response_deduplication_complete; it is captured only on "
                    "the post-POST HTTP response"
                )


@dataclass(frozen=True)
class FindingReadbackV1:
    """A complete supported-API Test/Finding read-back event.

    ``readback_ref`` is the evidence reference for the read-back; ``verified``
    must be explicitly True for the read-back to be settle evidence. The
    read-back is bound to exactly one ``test_id`` and one ``context_key``:
    an unscoped read-back is never settle evidence. The
    ``finding_ids``/``endpoint_ids`` tuples are the complete measured scope
    of that read-back (a verified empty set is honest: the Test genuinely
    has no findings); they are measured read-back outputs, never inferred
    UVM occurrence counts.
    """

    readback_ref: str
    verified: bool
    test_id: str
    context_key: str
    finding_ids: tuple = ()
    endpoint_ids: tuple = ()

    def __post_init__(self) -> None:
        if not isinstance(self.verified, bool):
            raise ValueError("verified must be an explicit bool")
        if not self.test_id:
            raise ValueError(
                "test_id is required: the read-back is bound to one Test"
            )
        if not self.context_key:
            raise ValueError(
                "context_key is required: the read-back is bound to one context"
            )
        if not isinstance(self.finding_ids, tuple) or not isinstance(
            self.endpoint_ids, tuple
        ):
            raise ValueError("finding_ids and endpoint_ids must be tuples")


@dataclass(frozen=True)
class ReconciliationEventV1:
    """A versioned verified supported-API reconciliation result.

    ``reconciliation_ref`` is the evidence reference for the supported-API
    read of the intended context; ``context_key`` is the scope the read was
    taken against; ``candidate_test_ids`` is the measured candidate result —
    the empty tuple is an observed empty result, not proof of non-execution.
    No lost-response retry follows from it; a fresh import may settle through
    ``settle_reconciliation_readback``.
    """

    schema_version: int
    reconciliation_ref: str
    context_key: str
    candidate_test_ids: tuple = ()

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version!r}")
        if not self.context_key:
            raise ValueError("context_key scope is required")
        if not isinstance(self.candidate_test_ids, tuple):
            raise ValueError("candidate_test_ids must be a tuple")
        for candidate in self.candidate_test_ids:
            if not isinstance(candidate, str) or not candidate:
                raise ValueError(
                    "candidate_test_ids must be non-empty Test IDs; a verified "
                    "absence is the empty tuple"
                )


@dataclass(frozen=True)
class FirstImportBaselineV1:
    """Supported-API Test inventory of the intended context before POST.

    A first import may use a lost-response Test read-back only if the
    pre-POST inventory was verified empty. The reference identifies the
    independently retained API evidence; the store records it before POST.
    """

    schema_version: int
    baseline_ref: str
    verified: bool
    context_key: str
    candidate_test_ids: tuple = ()

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version!r}")
        if not isinstance(self.verified, bool):
            raise ValueError("verified must be an explicit bool")
        if not self.context_key:
            raise ValueError("context_key scope is required")
        if not isinstance(self.candidate_test_ids, tuple):
            raise ValueError("candidate_test_ids must be a tuple")
        for candidate in self.candidate_test_ids:
            if not isinstance(candidate, str) or not candidate:
                raise ValueError("candidate_test_ids must contain non-empty Test IDs")


@dataclass(frozen=True)
class ReconciliationReadbackV1:
    """A versioned verified reconciliation read-back event.

    The supported-API read taken after a lost HTTP response to settle a
    quarantined first-import operation. ``readback_ref`` is the evidence
    reference, ``verified`` must be explicitly True, ``context_key`` is
    the read scope, ``candidate_test_ids`` is the measured candidate result
    (exactly one is required to settle; zero and multiple/ambiguous stay
    quarantined), ``deduplication_complete`` is
    the verified completion result, and ``finding_ids``/``endpoint_ids``
    are the complete measured Finding scope of the unique candidate (a
    verified empty set is honest); they are measured read-back outputs,
    never inferred UVM occurrence counts. The CE supported API
    (3.3.100/3.3.200) supplies no independently verifiable field proving
    the unique candidate write is this operation's write, so this event
    carries no such correlation: it is never proof for a lost reimport,
    which stays quarantined and unresolved.
    """

    schema_version: int
    readback_ref: str
    verified: bool
    context_key: str
    candidate_test_ids: tuple
    deduplication_complete: bool
    finding_ids: tuple = ()
    endpoint_ids: tuple = ()

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version!r}")
        if not isinstance(self.verified, bool):
            raise ValueError("verified must be an explicit bool")
        if not isinstance(self.deduplication_complete, bool):
            raise ValueError("deduplication_complete must be an explicit bool")
        if not self.context_key:
            raise ValueError("context_key scope is required")
        if not isinstance(self.candidate_test_ids, tuple):
            raise ValueError("candidate_test_ids must be a tuple")
        for candidate in self.candidate_test_ids:
            if not isinstance(candidate, str) or not candidate:
                raise ValueError(
                    "candidate_test_ids must be non-empty Test IDs; a verified "
                    "absence is the empty tuple"
                )
        if not isinstance(self.finding_ids, tuple) or not isinstance(
            self.endpoint_ids, tuple
        ):
            raise ValueError("finding_ids and endpoint_ids must be tuples")


@dataclass(frozen=True)
class OperationResult:
    """Outcome of a store command.

    ``outcome`` is one of: ``registered`` | ``duplicate`` | ``conflict`` |
    ``rejected`` | ``not_found`` | ``post_allowed`` | ``post_blocked`` |
    ``recorded`` | ``not_recorded`` | ``settled`` | ``not_settled`` |
    ``failed`` | ``not_failed`` | ``quarantined`` | ``not_quarantined`` |
    ``reconciled`` | ``not_reconciled``. (``duplicate`` and ``conflict``
    outcomes are registration outcomes.) ``operation`` is the stored
    revision the outcome refers to (the incoming op for rejections).
    """

    outcome: str
    operation: Optional[EngineImportOperationV1]
    reason: Optional[str] = None
    conflict_with: Optional[str] = None


def _bump(op: EngineImportOperationV1) -> int:
    return op.revision + 1


class OperationStore:
    """In-memory EngineImportOperationV1 store with the approved state
    machine.

    Serialises writes per context and per bound Test: while a context
    has an active operation (pending, quarantined or conflict) a different
    new operation for that context is rejected as an explicit conflict; a
    different context whose registered ``test_id`` matches a Test claimed
    by a response, an active request or a settled mapping is rejected.
    A definitive ``failed``
    request blocks nothing because it did not accept the write. The prior
    active mapping (last settled mapping revision for the context) is
    retained untouched by pending/quarantined operations and advanced only
    by a settled operation.

    In-memory only: nothing here is durable persistence or a live engine.
    """

    def __init__(self) -> None:
        self._by_id: dict[str, EngineImportOperationV1] = {}
        self._by_context: dict[str, list[str]] = {}
        # context_key -> (operation_id, mapping_revision) of the last
        # settled operation; the prior active mapping.
        self._active_mapping: dict[str, tuple[str, int]] = {}

    # -- queries ---------------------------------------------------------

    def get(self, operation_id: str) -> Optional[EngineImportOperationV1]:
        return self._by_id.get(operation_id)

    def for_context(self, context_key: str) -> list[EngineImportOperationV1]:
        return [self._by_id[oid] for oid in self._by_context.get(context_key, [])]

    def active_operation(self, context_key: str) -> Optional[EngineImportOperationV1]:
        for op in self.for_context(context_key):
            if op.status in _ACTIVE_STATUSES:
                return op
        return None

    def active_mapping_revision(self, context_key: str) -> Optional[int]:
        entry = self._active_mapping.get(context_key)
        return entry[1] if entry is not None else None

    # -- commands --------------------------------------------------------

    def register(self, op: EngineImportOperationV1) -> OperationResult:
        """Record the pre-POST context and payload digest.

        Idempotent for the same operation ID with an identical request:
        the full pre-POST context and payload digest (the registered Test
        ID and ``requested_at`` are part of the request); the Test bound on
        settle is a result and never changes the request. ``conflict``
        when the ID is reused with different bytes, context or request
        (including a changed ``requested_at``); rejected when the context
        already has an active operation, or when the registered Test
        is already claimed by an active operation or settled mapping in
        another context (serialise per context/Test).
        """
        if op.status != STATUS_PENDING:
            return OperationResult(
                "rejected",
                op,
                reason="a new operation must start pending; HTTP acceptance creates pending",
            )
        if op.post_issued:
            # Registration is the clean pre-POST state. An externally
            # pre-issued flag is not evidence that this store issued the
            # POST: it would let a caller record a response, quarantine
            # and settle a write the store never issued.
            return OperationResult(
                "rejected",
                op,
                reason=(
                    "registration is the clean pre-POST state; an externally "
                    "pre-issued flag is not evidence of an issued write — "
                    "the POST is issued only through issue_post"
                ),
            )
        if op.first_import_baseline_ref is not None:
            return OperationResult(
                "rejected", op,
                reason="a first-import baseline is recorded by this store before issue_post",
            )
        existing = self._by_id.get(op.operation_id)
        if existing is not None:
            if self._same_pre_post_context(existing, op):
                # Idempotent duplicate: reconciliation material, never a
                # second POST.
                return OperationResult("duplicate", existing)
            # Same operation ID, different bytes or context: explicit
            # conflict. The stored operation (if still actionable) is held
            # in conflict so the context stays write-blocked.
            retained = existing
            if existing.status in (STATUS_PENDING, STATUS_QUARANTINED):
                retained = replace(
                    existing, status=STATUS_CONFLICT, revision=_bump(existing)
                )
                self._store(retained)
            return OperationResult(
                "conflict",
                retained,
                conflict_with=existing.operation_id,
                reason=(
                    "operation_id reused with different payload or context; "
                    "retained as conflict, never silently replaced"
                ),
            )
        active = self.active_operation(op.context_key)
        if active is None and op.test_id:
            # A first import acquires its Test on response or settle. That
            # Test is also a serialisation key for later registrations.
            active = self._test_holder_elsewhere(op, op.test_id)
        if active is not None:
            return OperationResult(
                "conflict",
                op,
                conflict_with=active.operation_id,
                reason=(
                    f"write for {op.context_key} collides with active "
                    f"operation {active.operation_id} ({active.status}) for "
                    f"the same context or registered Test {op.test_id!r}; "
                    "serialise writes per context/Test"
                ),
            )
        prior = self.active_mapping_revision(op.context_key)
        prior_entry = self._active_mapping.get(op.context_key)
        if op.request_kind == REQUEST_REIMPORT and prior_entry is not None:
            mapped_test_id = self._by_id[prior_entry[0]].bound_test_id
            if mapped_test_id != op.test_id:
                return OperationResult(
                    "rejected", op,
                    reason=(
                        "reimport Test ID does not match the context's active "
                        f"mapped Test ID {mapped_test_id!r}"
                    ),
                )
        if op.request_kind == REQUEST_IMPORT:
            if op.test_id is not None:
                return OperationResult(
                    "rejected", op,
                    reason="a first import must auto-create a Test; test_id must be null",
                )
            if prior is not None:
                return OperationResult(
                    "rejected", op,
                    reason="a settled context already has a Test; use registered reimport",
                )
        if op.prior_mapping_revision is not None and op.prior_mapping_revision != prior:
            return OperationResult(
                "rejected",
                op,
                reason=(
                    "prior_mapping_revision does not match the active mapping "
                    f"for {op.context_key} (stored: {prior})"
                ),
            )
        stored = replace(op, prior_mapping_revision=prior)
        self._store(stored)
        self._by_context.setdefault(op.context_key, []).append(op.operation_id)
        return OperationResult("registered", stored)

    def record_first_import_baseline(
        self, operation_id: str, event: FirstImportBaselineV1
    ) -> OperationResult:
        """Record verified empty Test inventory before a first-import POST."""
        op = self._by_id.get(operation_id)
        if op is None:
            return OperationResult("not_found", None, reason="unknown operation_id")
        if op.request_kind != REQUEST_IMPORT or op.status != STATUS_PENDING or op.post_issued:
            return OperationResult(
                "not_recorded", op,
                reason="first-import baseline must precede the first POST",
            )
        if not isinstance(event, FirstImportBaselineV1):
            return OperationResult("not_recorded", op, reason="versioned baseline event required")
        if not event.baseline_ref or not event.verified or event.context_key != op.context_key:
            return OperationResult(
                "not_recorded", op,
                reason="verified baseline evidence for the intended context is required",
            )
        if event.candidate_test_ids:
            return OperationResult(
                "not_recorded", op,
                reason="preexisting Tests prevent proof of a fresh first import",
            )
        if op.first_import_baseline_ref is not None:
            return OperationResult(
                "duplicate" if op.first_import_baseline_ref == event.baseline_ref else "not_recorded",
                op,
                reason="first-import baseline is immutable once recorded",
            )
        stored = replace(op, first_import_baseline_ref=event.baseline_ref, revision=_bump(op))
        self._store(stored)
        return OperationResult("recorded", stored)

    def issue_post(self, operation_id: str) -> OperationResult:
        """Issue the single POST for this operation's payload.

        A pending operation that already issued a POST gets a
        ``post_blocked`` outcome: the same operation+payload never
        triggers a second POST; inspect the uncertain result before review.
        """
        op = self._by_id.get(operation_id)
        if op is None:
            return OperationResult("not_found", None, reason="unknown operation_id")
        if op.status != STATUS_PENDING:
            return OperationResult(
                "post_blocked", op, reason=f"operation is {op.status}; only pending operations issue POSTs"
            )
        if op.post_issued:
            return OperationResult(
                "post_blocked",
                op,
                reason=(
                    "POST already issued for this operation+payload; a lost "
                    "or uncertain response remains quarantined; no second "
                    "POST is authorised by an empty API candidate list"
                ),
            )
        stored = replace(
            op, post_issued=True, revision=_bump(op)
        )
        self._store(stored)
        return OperationResult("post_allowed", stored)

    def record_response(
        self,
        operation_id: str,
        response_ref: str,
        response_test_id: Optional[str] = None,
        deduplication_complete: Optional[bool] = None,
    ) -> OperationResult:
        """Record the HTTP response evidence.

        The first recorded response requires that the operation's POST was
        already issued: a response before ``issue_post`` is not evidence
        about this write and is rejected. The operation stays ``pending``:
        a response, even with completed deduplication, is not settle
        evidence on its own. Replaying the
        original captured response is idempotent, including after the
        deduplication flag advanced through a verified read-back: the
        replay is compared against the original captured response, never
        against later deduplication completion state. A conflicting second
        HTTP response (different ref, Test ID or captured completion flag)
        quarantines the operation (inconsistent candidates) and blocks
        settle until reconciliation; the first recorded response evidence is
        retained unchanged. Asynchronous deduplication completion is never
        updated here; use ``record_dedup_readback`` for that.
        """
        op = self._by_id.get(operation_id)
        if op is None:
            return OperationResult("not_found", None, reason="unknown operation_id")
        if op.status != STATUS_PENDING:
            return OperationResult(
                "not_recorded",
                op,
                reason=f"operation is {op.status}; responses are recorded for pending operations",
            )
        if op.response_ref is not None:
            if (
                op.response_ref == response_ref
                and op.response_test_id == response_test_id
                and op.response_deduplication_complete == deduplication_complete
            ):
                # Identical to the original captured response (the dedup
                # flag as captured, not the later read-back completion
                # state): idempotent replay, even after a verified
                # read-back advanced completion to true.
                return OperationResult(
                    "duplicate",
                    op,
                    reason="identical response already recorded",
                )
            # Inconsistent candidates: quarantine, retain the first response
            # evidence, and block settle and any second POST.
            stored = replace(
                op,
                status=STATUS_QUARANTINED,
                error_detail_ref=(
                    f"conflicting-response:{response_ref}"
                    f"(test_id={response_test_id!r}) vs "
                    f"{op.response_ref}(test_id={op.response_test_id!r})"
                ),
                revision=_bump(op),
            )
            self._store(stored)
            return OperationResult(
                "quarantined",
                stored,
                reason=(
                    "conflicting response evidence recorded for the same "
                    "operation; quarantined with the first response retained, "
                    "settle and any second POST blocked pending review"
                ),
            )
        if not response_ref:
            return OperationResult(
                "not_recorded", op, reason="response_ref is required"
            )
        if not op.post_issued:
            return OperationResult(
                "not_recorded",
                op,
                reason=(
                    "no POST issued for this operation yet; an HTTP response "
                    "cannot be recorded before issue_post"
                ),
            )
        if response_test_id and self._test_holder_elsewhere(op, response_test_id):
            stored = replace(
                op,
                status=STATUS_QUARANTINED,
                response_ref=response_ref,
                response_test_id=response_test_id,
                response_deduplication_complete=deduplication_complete,
                deduplication_complete=deduplication_complete,
                error_detail_ref="response Test is claimed by another context",
                revision=_bump(op),
            )
            self._store(stored)
            return OperationResult(
                "quarantined", stored,
                reason="response Test is claimed by another context; binding requires review",
            )
        stored = replace(
            op,
            response_ref=response_ref,
            response_test_id=response_test_id,
            deduplication_complete=deduplication_complete,
            response_deduplication_complete=deduplication_complete,
            revision=_bump(op),
        )
        self._store(stored)
        return OperationResult("recorded", stored)

    def record_dedup_readback(
        self,
        operation_id: str,
        readback_ref: str,
        deduplication_complete: bool,
    ) -> OperationResult:
        """Advance asynchronous deduplication completion from an explicit
        verified read-back (design flow 5: the importer can dispatch dedup
        asynchronously and ``async_wait`` may time out).

        A false/absent completion flag can advance to ``True`` only via
        this verified read-back, which must name its evidence
        (``readback_ref``); a second HTTP response is never the success
        evidence (use ``record_response``, which quarantines conflicts).
        Completion is monotonic: ``True`` is terminal and can never be
        re-recorded as ``False``. Pending operations only; a quarantined
        operation cannot use this pending-only completion path.
        """
        op = self._by_id.get(operation_id)
        if op is None:
            return OperationResult("not_found", None, reason="unknown operation_id")
        if op.status != STATUS_PENDING:
            return OperationResult(
                "not_recorded",
                op,
                reason=(
                    f"operation is {op.status}; deduplication completion is "
                    "only advanced from pending operations"
                ),
            )
        if not readback_ref:
            return OperationResult(
                "not_recorded", op, reason="verified read-back evidence ref is required"
            )
        if not isinstance(deduplication_complete, bool):
            return OperationResult(
                "not_recorded",
                op,
                reason="deduplication_complete must be an explicit bool read-back",
            )
        if op.deduplication_complete is True and not deduplication_complete:
            return OperationResult(
                "not_recorded",
                op,
                reason=(
                    "completion is monotonic: a verified True completion "
                    "cannot be re-recorded as False"
                ),
            )
        if op.deduplication_complete == deduplication_complete:
            return OperationResult(
                "duplicate",
                op,
                reason="identical deduplication completion already verified",
            )
        stored = replace(
            op,
            # Store the verified read-back value exactly: only an explicit
            # True completion event sets True; a verified False (dedup not
            # yet complete) records False and can never settle.
            deduplication_complete=deduplication_complete,
            deduplication_evidence_ref=readback_ref,
            revision=_bump(op),
        )
        self._store(stored)
        return OperationResult(
            "recorded",
            stored,
            reason=(
                "verified read-back recorded deduplication completion "
                f"={deduplication_complete!r}; only an explicit True "
                "completion event can settle"
            ),
        )

    def mark_uncertain(self, operation_id: str, reason: str) -> OperationResult:
        """Quarantine a lost/uncertain response (timeout, absent response,
        zero/multiple/inconsistent candidates). A quarantined operation
        blocks retries until reconciliation."""
        op = self._by_id.get(operation_id)
        if op is None:
            return OperationResult("not_found", None, reason="unknown operation_id")
        if op.status != STATUS_PENDING:
            return OperationResult(
                "not_quarantined",
                op,
                reason=f"operation is {op.status}; only pending operations quarantine",
            )
        if not op.post_issued:
            # A lost/uncertain response presumes an issued POST; quarantining
            # a never-issued write would manufacture a lost-response state
            # that a read-back could then settle.
            return OperationResult(
                "not_quarantined",
                op,
                reason=(
                    "no POST issued for this operation yet; a "
                    "lost/uncertain response requires an issued POST"
                ),
            )
        stored = replace(
            op,
            status=STATUS_QUARANTINED,
            error_detail_ref=reason,
            revision=_bump(op),
        )
        self._store(stored)
        return OperationResult(
            "quarantined",
            stored,
            reason="lost/uncertain response; second POST blocked while quarantined",
        )

    def reconcile(self, operation_id: str, event: ReconciliationEventV1) -> OperationResult:
        """Inspect a quarantined operation without authorising a retry,
        using a versioned verified supported-API reconciliation event
        (``ReconciliationEventV1``: evidence ref, read scope, and the
        measured candidate result for the intended context).

        A bare caller Boolean is never reconciliation evidence. A read
        taken against a different context refuses. A read that found any
        candidate Test refuses any retry (a fresh first import may settle
        through ``settle_reconciliation_readback``).
        Even zero candidates after a verified empty pre-POST baseline cannot
        prove an in-flight first import did not write. The operation stays
        quarantined; an empty Test list also never proves reimport
        non-execution.
        """
        op = self._by_id.get(operation_id)
        if op is None:
            return OperationResult("not_found", None, reason="unknown operation_id")
        if op.status != STATUS_QUARANTINED:
            return OperationResult(
                "not_reconciled",
                op,
                reason=f"operation is {op.status}; only quarantined operations reconcile",
            )
        if not isinstance(event, ReconciliationEventV1):
            return OperationResult(
                "not_reconciled",
                op,
                reason=(
                    "reconciliation requires a versioned verified supported-API "
                    "reconciliation event with scope and evidence; a bare "
                    "caller Boolean is never evidence"
                ),
            )
        if not event.reconciliation_ref:
            return OperationResult(
                "not_reconciled",
                op,
                reason="reconciliation evidence ref is required",
            )
        if event.context_key != op.context_key:
            return OperationResult(
                "not_reconciled",
                op,
                reason=(
                    "reconciliation read was taken against a different context; "
                    "it is not evidence about this operation's context"
                ),
            )
        if op.request_kind == REQUEST_REIMPORT:
            return OperationResult(
                "not_reconciled", op,
                reason=(
                    "an empty Test list cannot prove that reimport of a "
                    "preexisting Test did not execute; no second POST without "
                    "independent supported-API proof of non-execution"
                ),
            )
        if op.first_import_baseline_ref is None:
            return OperationResult(
                "not_reconciled", op,
                reason=(
                    "a lost first import needs a verified empty pre-POST "
                    "context baseline to identify a later fresh Test"
                ),
            )
        if event.candidate_test_ids:
            return OperationResult(
                "not_reconciled",
                op,
                reason=(
                    "reconciliation found candidate Tests; a unique fresh "
                    "candidate may settle through settle_reconciliation_readback"
                ),
            )
        return OperationResult(
            "not_reconciled", op,
            reason=(
                "zero API candidates do not prove the first import did not "
                "write or is not still in flight; the operation remains "
                "quarantined and no second POST is authorised"
            ),
        )

    def mark_failed(
        self, operation_id: str, error_code: str, error_detail_ref: str
    ) -> OperationResult:
        """Record a definitive rejected request (the engine rejected it;
        no Test was created). Terminal."""
        op = self._by_id.get(operation_id)
        if op is None:
            return OperationResult("not_found", None, reason="unknown operation_id")
        if op.status != STATUS_PENDING:
            return OperationResult(
                "not_failed",
                op,
                reason=f"operation is {op.status}; only pending operations fail",
            )
        stored = replace(
            op,
            status=STATUS_FAILED,
            error_code=error_code,
            error_detail_ref=error_detail_ref,
            revision=_bump(op),
        )
        self._store(stored)
        return OperationResult("failed", stored)

    def settle(
        self,
        operation_id: str,
        read_back_test_id: str,
        readback: FindingReadbackV1,
        mapping_revision: int,
    ) -> OperationResult:
        """Settle from a completed deduplication plus a matching
        supported-API Test/Finding read-back.

        The Finding scope is a complete ``FindingReadbackV1`` read-back
        event: it must name its evidence (``readback_ref``) and be an
        explicit verified read-back covering the full measured Finding
        scope; a verified empty set is allowed, but unverified emptiness
        and naked caller-supplied Finding IDs are never settle evidence.
        Refuses (stays non-settled) when: the response was lost/uncertain,
        deduplication is absent or false (0/false completion), the read-back
        Test ID is missing, the read-back Test ID disagrees with the
        response Test ID (inconsistent IDs), the read-back is not a complete
        verified event, or ``mapping_revision`` does not strictly advance
        the context's prior active mapping. A first import also requires a
        verified empty pre-POST Test inventory for its intended context,
        even when the HTTP response names a Test ID.
        """
        op = self._by_id.get(operation_id)
        if op is None:
            return OperationResult("not_found", None, reason="unknown operation_id")
        if op.status != STATUS_PENDING:
            return OperationResult(
                "not_settled",
                op,
                reason=f"operation is {op.status}; only pending operations settle",
            )
        if not op.post_issued:
            # Settling requires the issued write plus the post-write read-back
            #; a response-less, POST-less operation has no write to settle.
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "no POST issued for this operation; settle requires the "
                    "issued write plus a post-write read-back"
                ),
            )
        if not isinstance(readback, FindingReadbackV1):
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "settle evidence must be a complete FindingReadbackV1 "
                    "read-back event; naked caller-supplied Finding IDs are "
                    "never settle evidence"
                ),
            )
        if not readback.readback_ref:
            return OperationResult(
                "not_settled",
                op,
                reason="complete read-back evidence ref is required to settle",
            )
        if not readback.verified:
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "read-back is not an explicit verified event; unverified "
                    "emptiness (or any unverified scope) cannot settle — a "
                    "verified empty set is allowed, naked emptiness is not"
                ),
            )
        if op.response_ref is None:
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "no response recorded; a lost/uncertain response blocks "
                    "settle pending reconciliation"
                ),
            )
        if op.deduplication_complete is not True:
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "deduplication_complete is absent or false; 0/false "
                    "completion cannot settle"
                ),
            )
        if not read_back_test_id:
            return OperationResult(
                "not_settled",
                op,
                reason="read-back Test ID is required to settle",
            )
        if readback.test_id != read_back_test_id:
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "read-back event is bound to a different Test than the "
                    "settled Test ID; inconsistent bindings stay pending"
                ),
            )
        if readback.context_key != op.context_key:
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "read-back event context does not match the operation "
                    "context; unscoped or foreign-scope read-backs cannot settle"
                ),
            )
        if op.response_test_id is not None and op.response_test_id != read_back_test_id:
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "read-back Test ID does not match the response Test ID; "
                    "inconsistent IDs stay pending"
                ),
            )
        if op.request_kind == REQUEST_IMPORT and op.first_import_baseline_ref is None:
            return OperationResult(
                "not_settled", op,
                reason=(
                    "first import requires a verified empty pre-POST baseline "
                    "for its context; a response Test ID alone does not prove "
                    "the Test is fresh"
                ),
            )
        if self._test_bound_elsewhere(op, read_back_test_id):
            return OperationResult(
                "not_settled", op,
                reason=(
                    "read-back Test is claimed by an active or settled "
                    "operation in another context"
                ),
            )
        if (
            op.request_kind == REQUEST_REIMPORT
            and op.test_id is not None
            and op.test_id != read_back_test_id
        ):
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "read-back Test ID does not match the registered reimport "
                    "Test ID; an absent response Test ID never waives the "
                    "registered Test; inconsistent IDs stay pending"
                ),
            )
        prior = self.active_mapping_revision(op.context_key)
        if (
            not isinstance(mapping_revision, int)
            or mapping_revision < 1
            or (prior is not None and mapping_revision <= prior)
        ):
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "mapping_revision must be a positive integer strictly "
                    f"exceeding the prior active mapping revision ({prior})"
                ),
            )
        stored = replace(
            op,
            status=STATUS_SETTLED,
            bound_test_id=read_back_test_id,  # a result; the request test_id is immutable
            finding_ids=readback.finding_ids,
            endpoint_ids=readback.endpoint_ids,
            mapping_revision=mapping_revision,
            settle_readback_ref=readback.readback_ref,
            revision=_bump(op),
        )
        self._store(stored)
        self._active_mapping[op.context_key] = (op.operation_id, mapping_revision)
        return OperationResult(
            "settled",
            stored,
            reason=(
                "completed deduplication plus a complete verified "
                "Test/Finding read-back; prior mapping revision retained"
            ),
        )

    def settle_reconciliation_readback(
        self,
        operation_id: str,
        readback: ReconciliationReadbackV1,
        mapping_revision: int,
    ) -> OperationResult:
        """Settle a quarantined operation from a completed engine write
        discovered by a supported-API read-back after a lost HTTP response.

        The evidence is a versioned verified ``ReconciliationReadbackV1``
        read-back event bound to the context and naming its evidence
        (``readback_ref``); naked caller-supplied Finding IDs are never
        settle evidence. The event is the unique context/Test/Finding
        evidence for the write the already-issued POST completed; no new
        POST is possible (the operation settles terminal, which blocks
        ``issue_post``).

        Only a first import with a verified empty pre-POST context can settle
        this way: a single fresh candidate in that context is the write.
        A lost reimport never settles from
        a read-back: the CE supported API (3.3.100/3.3.200) supplies no
        independently verifiable write-provenance field, a caller-supplied
        source-run correlation is not supported-API proof, and a stale
        preexisting Test/Finding set must never advance the revision —
        the reimport stays quarantined and safely unresolved.

        Refuses (stays quarantined) when: the operation
        is not quarantined, the event is not a complete
        ``ReconciliationReadbackV1``, the evidence ref is missing, the
        read-back is not explicitly verified, the read-back context does
        not match the operation context, the read-back found zero
        candidates or multiple
        candidates, the candidate disagrees with the registered reimport
        Test or with the first recorded response Test ID, the operation is
        a reimport of a registered Test (see above), deduplication
        completion is not a verified ``True`` read-back, or
        ``mapping_revision`` does not strictly advance the context's prior
        active mapping. The read-back evidence ref is stored as the settle
        evidence; no HTTP response is fabricated and no occurrence count
        is inferred.
        """
        op = self._by_id.get(operation_id)
        if op is None:
            return OperationResult("not_found", None, reason="unknown operation_id")
        if op.status != STATUS_QUARANTINED:
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    f"operation is {op.status}; only quarantined operations "
                    "settle from a reconciliation read-back"
                ),
            )
        if not isinstance(readback, ReconciliationReadbackV1):
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "settle evidence must be a complete ReconciliationReadbackV1 "
                    "read-back event; naked caller-supplied Finding IDs are "
                    "never settle evidence"
                ),
            )
        if not readback.readback_ref:
            return OperationResult(
                "not_settled",
                op,
                reason="reconciliation read-back evidence ref is required",
            )
        if not readback.verified:
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "read-back is not an explicit verified event; unverified "
                    "read-backs cannot settle"
                ),
            )
        if readback.context_key != op.context_key:
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "read-back event context does not match the operation "
                    "context; unscoped or foreign-scope read-backs cannot settle"
                ),
            )
        candidates = tuple(readback.candidate_test_ids)
        if not candidates:
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "read-back found no completed Test; the operation stays "
                    "quarantined because absence cannot prove non-execution"
                ),
            )
        if len(candidates) > 1:
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "multiple candidate Tests for the intended context; "
                    "ambiguous matches stay quarantined"
                ),
            )
        read_back_test_id = candidates[0]
        if (
            op.request_kind == REQUEST_REIMPORT
            and op.test_id is not None
            and op.test_id != read_back_test_id
        ):
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "read-back Test does not match the registered reimport "
                    "Test; stays quarantined"
                ),
            )
        if op.response_test_id is not None and op.response_test_id != read_back_test_id:
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "read-back Test does not match the first recorded response "
                    "Test ID; stays quarantined"
                ),
            )
        if op.request_kind == REQUEST_REIMPORT:
            # The registered Test's preexisting Findings prove nothing about
            # this write: the supported API carries no verifiable
            # write-provenance field, so a matching read-back may be stale
            # data. Stay quarantined; no revision may advance on it.
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "a lost reimport cannot be proven from a read-back: the "
                    "CE supported API supplies no independently verifiable "
                    "write-provenance field and a caller-supplied source-run "
                    "correlation is not supported-API proof; a stale "
                    "preexisting Test/Finding set never settles this write, "
                    "so the operation stays quarantined and safely unresolved"
                ),
            )
        if op.first_import_baseline_ref is None:
            return OperationResult(
                "not_settled", op,
                reason=(
                    "fresh Test is unproven: first import needs a verified "
                    "empty pre-POST context baseline; stays quarantined"
                ),
            )
        if self._test_bound_elsewhere(op, read_back_test_id):
            return OperationResult(
                "not_settled", op,
                reason="candidate Test is already bound to another settled operation",
            )
        if not readback.deduplication_complete:
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "verified deduplication completion (true) from the "
                    "read-back is required to settle"
                ),
            )
        prior = self.active_mapping_revision(op.context_key)
        if (
            not isinstance(mapping_revision, int)
            or mapping_revision < 1
            or (prior is not None and mapping_revision <= prior)
        ):
            return OperationResult(
                "not_settled",
                op,
                reason=(
                    "mapping_revision must be a positive integer strictly "
                    f"exceeding the prior active mapping revision ({prior})"
                ),
            )
        stored = replace(
            op,
            status=STATUS_SETTLED,
            bound_test_id=read_back_test_id,  # a result; the request test_id is immutable
            finding_ids=tuple(readback.finding_ids),
            endpoint_ids=tuple(readback.endpoint_ids),
            mapping_revision=mapping_revision,
            deduplication_complete=True,
            deduplication_evidence_ref=readback.readback_ref,
            settle_readback_ref=readback.readback_ref,
            revision=_bump(op),
        )
        self._store(stored)
        self._active_mapping[op.context_key] = (op.operation_id, mapping_revision)
        return OperationResult(
            "settled",
            stored,
            reason=(
                "completed write discovered by a unique context/Test/Finding "
                "read-back; settled without a new POST; prior mapping "
                "revision retained"
            ),
        )

    # -- internals -------------------------------------------------------

    def _store(self, op: EngineImportOperationV1) -> None:
        self._by_id[op.operation_id] = op

    def _test_holder_elsewhere(
        self, op: EngineImportOperationV1, test_id: str
    ) -> Optional[EngineImportOperationV1]:
        for other in self._by_id.values():
            if other.operation_id == op.operation_id or other.context_key == op.context_key:
                continue
            if other.status in _ACTIVE_STATUSES and test_id in (
                other.test_id, other.response_test_id, other.bound_test_id
            ):
                return other
            if other.status == STATUS_SETTLED and other.bound_test_id == test_id:
                return other
        return None

    def _test_bound_elsewhere(self, op: EngineImportOperationV1, test_id: str) -> bool:
        return self._test_holder_elsewhere(op, test_id) is not None

    @staticmethod
    def _same_pre_post_context(
        stored: EngineImportOperationV1, incoming: EngineImportOperationV1
    ) -> bool:
        """The full required request: pre-POST context, payload digest and
        request identity.

        ``requested_at`` is part of the request (a changed timestamp is a
        conflict, not a duplicate). ``test_id`` is the registered Test
        request context and is immutable: the Test bound on settle is a
        result (``bound_test_id``), never a request mutation. Response
        evidence, mapping, status and all result fields are excluded:
        re-sending the stored request after its revision advanced is a
        duplicate, not a context change.
        """
        return all(
            getattr(stored, name) == getattr(incoming, name)
            for name in (
                "context_key",
                "source_run_id",
                "scan_type",
                "payload_sha256",
                "parser_config_version",
                "engine_release",
                "request_kind",
                "test_id",  # the registered Test is immutable request context
                "requested_at",  # the request instant is part of the request
            )
        )
