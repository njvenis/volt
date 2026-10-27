"""UVM occurrence-to-engine links (EngineOccurrenceLinkV1) and their store.

In-memory contract code for the CR-04 occurrence-preservation boundary
(CR-02/03 identity preservation carried by the stable UVM occurrence IDs).
Pure stdlib, no HTTP, no persistence, no engine calls. The contract follows
``openspec/changes/g1-engine-identity-contracts/design.md`` (the
``EngineOccurrenceLinkV1`` row of the Version 1 shared contracts table):

- a versioned many-to-many link between a retained UVM occurrence and the
  engine record that represents it: multiple occurrences may share a
  Finding, and one occurrence may have several engine records;
- endpoint ID is optional because some parsers do not create endpoints;
- ``cr04_proof`` reports only caller-requested occurrences. Without a trusted
  actionable-occurrence manifest, exhaustive CR-04 proof stays pending;
- an ``active`` link is a retained candidate, not verified CR-04 proof.
  Flat supported-API Finding and Endpoint ID sets cannot establish that an
  Endpoint belongs to the linked Finding. Even a sole, measured Endpoint or
  a caller-supplied component locator leaves proof pending. Verification
  needs a trusted, scoped supported-API association binding the specific
  Finding to its Endpoint or component and the retained source occurrence;
- CR-04 proof (``cr04_proof``) binds to the authoritative stored operation
  (``uvm.engine.operation.OperationStore``) and its verified scoped
  Finding *and Endpoint* read-back scope: a fabricated operation ID or
  status, a Finding outside the stored Finding read-back scope, or an
  Endpoint outside the stored Endpoint read-back scope can never yield
  ``verified`` — they yield ``pending`` where evidence is unavailable.
  The current supported-API read-back measures flat Findings and Endpoints,
  never their binding or component locators: every effective association
  stays ``pending``; recording a link
  derives the operation status from the authoritative store, so a caller
  can never claim ``settled`` for an operation the store holds pending;
- with caller-supplied parsed ``FindingDetailAssociationV1`` objects
  (synthetic/retained evidence bytes; never a live CE proof) the store
  offers a bounded diagnostic only: ``pair_observed`` reports whether the
  supplied parsed bytes show a distinct per-occurrence Finding↔Endpoint
  pair (settled CURRENT stored mapping, an active effective link, exact
  canonical decimal string forms of the bound Test and the link
  Finding/Endpoint, per-Finding Endpoint membership in the parsed
  ``endpoint_ids``, and no indistinguishably shared pair). That diagnostic
  never verifies CR-04: until a separately trusted actionable-occurrence
  manifest and live API provenance exist, every effective link stays
  ``pending`` and ``exhaustive_status`` stays ``pending``.
- pending/quarantined operations never delete or supersede the prior active
  link; a settled reimport may supersede only within the same registered
  context and Test at a strictly newer active mapping revision;

CE 3.3.100/3.3.200 synthetic readbacks (6 Qualys Findings / 3 host-only
Endpoints; port-only rows sharing one hash; Sysdig components without
Endpoints) are the fixtures this contract is modelled against; they are
synthetic evidence of engine behaviour, not proof of UVM occurrence
preservation. Nothing here is durable persistence, live API integration or
external-system evidence.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Optional

from uvm.engine.association import FindingDetailAssociationV1
from uvm.engine.operation import (
    SCHEMA_VERSION,
    STATUS_FAILED,
    STATUS_SETTLED,
    OperationStore,
    _STATUSES,
)

# Link mapping states (distinct from operation statuses: pending/settled/
# failed/quarantined/conflict). A link is effective until superseded.
LINK_PENDING = "pending"
LINK_ACTIVE = "active"
LINK_SUPERSEDED = "superseded"
_LINK_STATUSES = (LINK_PENDING, LINK_ACTIVE, LINK_SUPERSEDED)

# CR-04 proof results for one actionable occurrence of a settled operation.
PROOF_VERIFIED = "verified"
PROOF_PENDING = "pending"
PROOF_FAILED = "failed"


@dataclass(frozen=True)
class Cr04ProofResult(Mapping[str, str]):
    """Per-request occurrence results; exhaustive CR-04 proof is unavailable.

    The caller supplies ``occurrence_ids``, so omitted actionable occurrences
    cannot be detected. A trusted source manifest is not carried by the
    current operation contract. Do not report an exhaustive pass from this
    result, even if every requested occurrence is verified.
    """

    occurrence_ids: tuple[str, ...]
    per_occurrence: dict[str, str]
    scope: str = "requested_occurrences"
    exhaustive_status: str = PROOF_PENDING

    def __getitem__(self, occurrence_id: str) -> str:
        return self.per_occurrence[occurrence_id]

    def __iter__(self):
        return iter(self.per_occurrence)

    def __len__(self) -> int:
        return len(self.per_occurrence)


def _require_uuid(value, name: str) -> None:
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        raise ValueError(f"{name} must be a UUID, got {value!r}") from None


def _require_instant(value: datetime, name: str) -> None:
    if value is None or value.tzinfo is None:
        raise ValueError(f"{name} must be a timezone-aware UTC instant")


@dataclass(frozen=True)
class EngineOccurrenceLinkV1:
    """One versioned link from a retained UVM occurrence to the engine
    record that represents it. Immutable; corrections supersede with a new
    link and the store retains the old revision as history.

    ``mapping_status``: ``active`` is a candidate association beyond the
    Finding (an Endpoint or a non-null component locator plus retained UVM
    evidence); it is not CR-04 proof. The current flat Finding/Endpoint
    read-back verifies neither a pair nor a component locator. ``pending``
    is recorded but not yet distinguishable (CR-04 proof pending);
    ``superseded`` is history (store-assigned only, with ``effective_until``).
    """

    # required
    schema_version: int
    link_id: str  # stable UVM UUID
    revision: int
    operation_id: str  # the EngineImportOperationV1 that produced the record
    occurrence_id: str  # retained UVM occurrence (CR-02/03 stable ID)
    finding_id: str  # engine Finding ID (measured read-back, never a count)
    evidence_sha256: str  # retained UVM source/evidence digest
    effective_from: datetime
    mapping_status: str
    # optional / conditional
    endpoint_id: Optional[str] = None  # some parsers create no endpoints
    component_locator: Optional[str] = None  # null is explicit: unknown
    effective_until: Optional[datetime] = None  # set when superseded
    supersedes_link_id: Optional[str] = None  # correction; history retained
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version!r}")
        _require_uuid(self.link_id, "link_id")
        _require_uuid(self.operation_id, "operation_id")
        _require_uuid(self.occurrence_id, "occurrence_id")
        if self.supersedes_link_id is not None:
            _require_uuid(self.supersedes_link_id, "supersedes_link_id")
        if self.revision < 1:
            raise ValueError("revision must be a positive integer")
        if not self.finding_id:
            raise ValueError("finding_id is required")
        if not self.evidence_sha256:
            raise ValueError("evidence_sha256 (retained UVM evidence) is required")
        _require_instant(self.effective_from, "effective_from")
        if self.effective_until is not None:
            _require_instant(self.effective_until, "effective_until")
            if self.effective_until < self.effective_from:
                raise ValueError("effective_until must not precede effective_from")
        if self.mapping_status not in _LINK_STATUSES:
            raise ValueError(
                f"mapping_status must be one of {_LINK_STATUSES}, "
                f"got {self.mapping_status!r}"
            )
        for name in ("endpoint_id", "component_locator"):
            value = getattr(self, name)
            if value is not None and not value:
                raise ValueError(f"{name} must be a non-empty string or explicit null")
        if self.mapping_status == LINK_SUPERSEDED and self.effective_until is None:
            raise ValueError(
                "a superseded link must carry effective_until (store-assigned)"
            )


@dataclass(frozen=True)
class LinkResult:
    """Outcome of a store command.

    ``outcome`` is one of: ``recorded`` | ``rejected`` | ``duplicate`` |
    ``conflict`` | ``not_found``. ``link`` is the stored revision the
    outcome refers to (the incoming link for rejections).
    """

    outcome: str
    link: Optional[EngineOccurrenceLinkV1]
    reason: Optional[str] = None


class LinkStore:
    """In-memory EngineOccurrenceLinkV1 store with the approved CR-04
    proof rules.

    - an ``active`` candidate link is accepted only from a ``settled``
      operation and only when it names a distinguishable association beyond
      the Finding: an Endpoint ID or a non-null component locator (endpoint
      ID is optional because some parsers create no endpoints); a Finding ID
      alone, or an all-null association, is recorded at most as
      ``pending``;
    - ``record`` derives the operation status from the authoritative
      ``OperationStore``, never from the caller: an operation unknown to the
      store is ``not_found``, and a pending/quarantined/conflict operation as
      stored cannot produce an active link or supersede;
    - CR-04 proof is computed at proof time and binds to the authoritative
      stored operation. The flat read-back scope alone never verifies a
      link: every effective link stays ``pending`` and
      ``exhaustive_status`` is ``pending`` in every case, until a
      separately trusted actionable-occurrence manifest and live API
      provenance exist. The ``pair_observed`` diagnostic over
      caller-supplied parsed associations (synthetic/retained evidence
      bytes, never a live CE proof) only reports whether those bytes show
      the pair; it never flips the proof result;
    - a pending/quarantined (or conflict) operation may record only
      ``pending`` links; a ``pending`` link never supersedes an active link,
      even when its operation is settled;
      a failed operation created no engine records and records nothing;
    - a settled reimport may supersede the previous operation's currently
      effective link for the same occurrence only within the same registered
      context and bound Test at a strictly newer active mapping revision, in
      append-only history; same-operation corrections also require that
      operation to remain the current mapping. The old revision is retained
      as ``superseded`` with ``effective_until``.

    Engine Finding/endpoint cardinality is a measured output, never a UVM
    occurrence count. In-memory only: nothing here is durable persistence or
    a live engine.
    """

    def __init__(self) -> None:
        self._by_id: dict[str, EngineOccurrenceLinkV1] = {}

    # -- queries ---------------------------------------------------------

    def get(self, link_id: str) -> Optional[EngineOccurrenceLinkV1]:
        return self._by_id.get(link_id)

    def for_operation(self, operation_id: str) -> list[EngineOccurrenceLinkV1]:
        return [l for l in self._by_id.values() if l.operation_id == operation_id]

    def for_occurrence(
        self, occurrence_id: str
    ) -> list[EngineOccurrenceLinkV1]:
        return [l for l in self._by_id.values() if l.occurrence_id == occurrence_id]

    def history(self, link_id: str) -> list[EngineOccurrenceLinkV1]:
        """The append-only supersession chain a link belongs to: oldest
        (now superseded) through newest. Empty when unknown."""
        node = self._by_id.get(link_id)
        if node is None:
            return []
        root = node
        while root.supersedes_link_id is not None:
            prev = self._by_id.get(root.supersedes_link_id)
            if prev is None:
                break
            root = prev
        chain = [root]
        while True:
            successor = next(
                (
                    l
                    for l in self._by_id.values()
                    if l.supersedes_link_id == root.link_id
                ),
                None,
            )
            if successor is None:
                break
            root = successor
            chain.append(root)
        return chain

    def is_shared(
        self, operation_id: str, occurrence_id: str, link: EngineOccurrenceLinkV1
    ) -> bool:
        """True when another occurrence of the same operation has an
        effective link indistinguishable from this one at proof time.

        Only the measured Endpoint decides: a caller-supplied component
        locator is never independently bound by the parsed supported-API
        association, so it cannot distinguish a shared pair — two invented
        locators on the same measured Endpoint, and a locator-versus-none
        asymmetry on it, are both indistinguishably shared. A *distinct*
        measured Endpoint carries the distinction (with or without a
        locator). A locator-less association rests on its Endpoint: a
        shared host-only Endpoint (the port appears only in the
        description) never proves distinct portions. This diagnostic
        cannot establish CR-04 proof: the current read-back does not bind
        any Endpoint to a specific Finding or source record."""
        for other in self._by_id.values():
            if (
                other.operation_id != operation_id
                or other.occurrence_id == occurrence_id
                or other.mapping_status == LINK_SUPERSEDED
            ):
                continue
            if link.endpoint_id and other.endpoint_id == link.endpoint_id:
                return True
        return False

    def cr04_proof(
        self,
        operations,
        operation_id: str,
        occurrence_ids,
    ) -> Cr04ProofResult:
        """Proof for caller-requested occurrences, never exhaustive CR-04 proof.

        ``operations`` must be the authoritative
        :class:`uvm.engine.operation.OperationStore`. The operation status
        and read-back scopes are read from the stored operation, never
        supplied by the caller: an unknown operation, or a stored operation
        that is not ``settled``, yields ``pending`` for every occurrence —
        a fabricated operation ID or status can never yield ``verified``.

        The flat Finding and Endpoint read-back scopes cannot prove a
        specific pair. Caller-supplied parsed associations are synthetic/
        retained evidence bytes, never a live CE proof, and they change
        nothing here: every effective link stays ``pending`` and
        ``exhaustive_status`` stays ``pending`` until a separately trusted
        actionable-occurrence manifest and live API provenance exist. Use
        :meth:`pair_observed` to check whether supplied parsed bytes show
        a pair; it is a diagnostic only. ``failed`` means no effective link
        was recorded for the requested occurrence.
        """
        requested = tuple(dict.fromkeys(occurrence_ids))
        stored = operations.get(operation_id)
        if stored is None or stored.status != STATUS_SETTLED:
            return Cr04ProofResult(
                requested, {occ: PROOF_PENDING for occ in requested}
            )
        result = {}
        for occurrence_id in requested:
            effective = [
                l
                for l in self.for_operation(operation_id)
                if l.occurrence_id == occurrence_id
                and l.mapping_status != LINK_SUPERSEDED
            ]
            result[occurrence_id] = PROOF_PENDING if effective else PROOF_FAILED
        return Cr04ProofResult(requested, result)

    def pair_observed(
        self,
        operations,
        operation_id: str,
        occurrence_id: str,
        associations,
    ) -> bool:
        """Diagnostic only: whether the caller-supplied parsed
        :class:`uvm.engine.association.FindingDetailAssociationV1` objects
        (synthetic/retained evidence bytes — never a live CE proof) show
        this occurrence's active link as a distinct per-occurrence
        Finding↔Endpoint pair of the stored operation.

        ``True`` never verifies CR-04: it only reports that the supplied
        parsed bytes show the pair. ``cr04_proof`` stays ``pending``
        regardless, until a separately trusted actionable-occurrence
        manifest and live API provenance exist. Any value that is not a
        parsed DTO is rejected. The observation requires ALL of:

        - the stored operation is ``settled`` AND is the current active
          mapping of its registered context — a stale mapping revision is
          not observed;
        - the occurrence has an ``active`` link in this store: a
          ``pending`` or ``superseded`` link is not observed;
        - the stored bound Test equals the association's Test ID and the
          link Finding equals the association's Finding ID in exact
          canonical decimal string form, and the link Finding and Endpoint
          are inside the stored read-back scopes;
        - the association's CE release exactly matches the stored
          operation's engine_release — bytes from another release cannot
          show this operation's pair;
        - the link Endpoint is in that specific Finding's parsed
          ``endpoint_ids`` (per-Finding membership, not the flat Test
          pool);
        - the pair is not indistinguishably shared: host-only sharing or a
          fabricated component distinction that leaves the same measured
          Endpoint+component pair never observes.
        """
        stored = operations.get(operation_id)
        if (
            stored is None
            or stored.status != STATUS_SETTLED
            or stored.mapping_revision is None
            or operations.active_mapping_revision(stored.context_key)
            != stored.mapping_revision
        ):
            return False
        associations = list(associations)
        for assoc in associations:
            if not isinstance(assoc, FindingDetailAssociationV1):
                raise ValueError(
                    "associations must be parsed "
                    "FindingDetailAssociationV1 objects"
                )
        finding_scope = {str(fid) for fid in stored.finding_ids}
        endpoint_scope = {str(eid) for eid in stored.endpoint_ids}
        for link in self.for_operation(operation_id):
            if (
                link.occurrence_id != occurrence_id
                or link.mapping_status != LINK_ACTIVE
            ):
                continue
            if self._pair_shown_by(
                link, stored, finding_scope, endpoint_scope, associations
            ):
                return True
        return False

    def _pair_shown_by(
        self,
        link: EngineOccurrenceLinkV1,
        stored,  # stored EngineImportOperationV1
        finding_scope: set,
        endpoint_scope: set,
        associations,
    ) -> bool:
        """Whether the supplied parsed associations show one active link as
        a distinct Finding↔Endpoint pair of the stored operation
        (diagnostic only; never CR-04 verification)."""
        if link.endpoint_id is None:
            return False  # endpoint-less component link: no pair to show
        # Exact canonical decimal string forms, never padded or relabelled:
        # the association's integer IDs and the stored bound Test match the
        # link only through their canonical string form.
        if link.finding_id not in finding_scope or link.endpoint_id not in endpoint_scope:
            return False  # outside the stored read-back scope
        if self.is_shared(stored.operation_id, link.occurrence_id, link):
            return False  # indistinguishably shared pair (e.g. host-only)
        for assoc in associations:
            if str(assoc.test_id) != stored.bound_test_id:
                continue
            if assoc.ce_release != stored.engine_release:
                continue  # exact release match: other-release bytes show nothing
            if str(assoc.finding_id) != link.finding_id:
                continue
            if link.endpoint_id in {str(eid) for eid in assoc.endpoint_ids}:
                return True
        return False

    # -- commands --------------------------------------------------------

    def record(
        self, link: EngineOccurrenceLinkV1, operations: OperationStore
    ) -> LinkResult:
        """Record a link (or a correction when ``supersedes_link_id`` is
        set) against the named operation as the authoritative
        :class:`OperationStore` holds it.

        The operation status is derived from the stored operation, never
        supplied by the caller: an operation unknown to the store is
        ``not_found`` (a fabricated operation can never record a link), and
        a pending/quarantined/conflict operation as stored cannot produce
        an active link or supersede. Idempotent for the exact same link
        DTO; a reused ``link_id`` with a different body is ``conflict``. A
        correction is recorded only from a settled operation, must target
        the same occurrence, and may cross operations: a settled reimport
        supersedes the previous operation's currently effective link in
        append-only history. A pending/quarantined operation never
        supersedes or deletes the prior active link.
        """
        stored = operations.get(link.operation_id)
        if stored is None:
            return LinkResult(
                "not_found",
                link,
                reason=(
                    f"operation_id {link.operation_id} is unknown to the "
                    "authoritative OperationStore; a link cannot name a "
                    "fabricated operation"
                ),
            )
        operation_status = stored.status
        if operation_status == STATUS_FAILED:
            return LinkResult(
                "rejected",
                link,
                reason=(
                    "a failed operation is a definitive rejected request: "
                    "it created no engine records to link"
                ),
            )
        existing = self._by_id.get(link.link_id)
        if existing is not None:
            if existing == link:
                return LinkResult(
                    "duplicate",
                    existing,
                    reason="identical link already recorded",
                )
            return LinkResult(
                "conflict",
                existing,
                reason=(
                    "link_id reused with a different body; the recorded "
                    "link is retained, never silently replaced"
                ),
            )
        if link.supersedes_link_id is not None:
            if operation_status != STATUS_SETTLED:
                return LinkResult(
                    "rejected",
                    link,
                    reason=(
                        f"a {operation_status} operation cannot supersede the "
                        "prior active link; corrections are recorded only from "
                        "a settled operation"
                    ),
                )
            if link.mapping_status != LINK_ACTIVE:
                return LinkResult(
                    "rejected", link,
                    reason="a pending link cannot supersede the prior active link; only an active replacement can supersede",
                )
            if (
                stored.mapping_revision is None
                or operations.active_mapping_revision(stored.context_key)
                != stored.mapping_revision
            ):
                return LinkResult(
                    "rejected", link,
                    reason="supersession requires the operation's active settled mapping revision",
                )
            target = self._by_id.get(link.supersedes_link_id)
            if target is None:
                return LinkResult(
                    "not_found",
                    link,
                    reason="supersedes_link_id is unknown to this store",
                )
            if target.mapping_status == LINK_SUPERSEDED:
                return LinkResult(
                    "rejected",
                    link,
                    reason=(
                        "the prior link is already superseded; history is "
                        "append-only and only the currently effective link "
                        "can be superseded"
                    ),
                )
            if target.occurrence_id != link.occurrence_id:
                return LinkResult(
                    "rejected",
                    link,
                    reason="a correction must concern the same occurrence",
                )
            if target.operation_id != link.operation_id:
                prior_op = operations.get(target.operation_id)
                if prior_op is None or prior_op.status != STATUS_SETTLED:
                    return LinkResult(
                        "rejected", link,
                        reason="cross-operation supersession needs the prior settled operation in the authoritative store",
                    )
                if (
                    stored.context_key != prior_op.context_key
                    or stored.bound_test_id != prior_op.bound_test_id
                    or not stored.bound_test_id
                ):
                    return LinkResult(
                        "rejected", link,
                        reason="cross-operation supersession requires the same registered context and bound Test",
                    )
                if (
                    stored.mapping_revision is None
                    or prior_op.mapping_revision is None
                    or stored.mapping_revision <= prior_op.mapping_revision
                    or operations.active_mapping_revision(stored.context_key)
                    != stored.mapping_revision
                ):
                    return LinkResult(
                        "rejected", link,
                        reason="cross-operation supersession requires the strictly newer active settled mapping revision",
                    )
        if link.mapping_status == LINK_ACTIVE:
            if operation_status != STATUS_SETTLED:
                return LinkResult(
                    "rejected",
                    link,
                    reason=(
                        f"a {operation_status} operation cannot produce "
                        "an active candidate link; only a settled operation "
                        "does, and it never deletes the prior active link"
                    ),
                )
            if link.endpoint_id is None and link.component_locator is None:
                return LinkResult(
                    "rejected",
                    link,
                    reason=(
                        "a shared Finding ID alone never proves CR-04: a "
                        "active candidate needs an Endpoint ID or "
                        "a non-null component locator plus the retained UVM "
                        "evidence; record it as pending instead"
                    ),
                )
        if link.supersedes_link_id is not None:
            target = self._by_id[link.supersedes_link_id]
            superseded = replace(
                target,
                mapping_status=LINK_SUPERSEDED,
                effective_until=link.effective_from,
                revision=target.revision + 1,
            )
            self._by_id[target.link_id] = superseded
        self._by_id[link.link_id] = link
        return LinkResult(
            "recorded",
            link,
            reason=(
                "correction recorded; prior link retained as superseded history"
                if link.supersedes_link_id is not None
                else None
            ),
        )
