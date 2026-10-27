"""Source-neutral actionable-occurrence manifest contract (G1 CR-03/04, FR-ID-02).

Contract-only module, approved V1 policy: the user approved the strict V1
manifest rule (proposal commit ``a076019``; decision record
``evidence/G1/manifest-policy-approval.md`` at ``7f0b497``). Nothing here
is live DefectDojo CE provenance, payload-serialization proof or a G1 gate
claim, and this module **never returns ``verified``** and exposes no
``cr04_proof``.

The contract treats a sealed, consistent snapshot of the complete retained
``(source_family, source_account_id, run_id)`` inventory as its input. The
``InventorySealV1`` records the retention-order high watermark and includes
every conflict holder; any newly retained row invalidates the seal (the
high watermark or row count stops matching) and requires a new snapshot
and operation. Before an import is issued, **every** retained row —
including conflict holders — receives exactly one immutable, versioned
disposition tied to the exact payload bytes and operation ID:

- ``included``: the row has a safe current (head-revision, matched/new)
  resolution and contributes to the import payload. The disposition
  records its observation ID, source position, retained evidence digest,
  resolution ID/revision and occurrence ID. A retained row with
  ``ingest_outcome == "conflict"`` is never included, even when a matched
  or new resolution is supplied for it.
- ``excluded_reviewed``: **unapproved in this slice.** Only a row
  demonstrably classed as non-vulnerability control/metadata by a
  trusted, versioned source rule may ever be omitted. Without a trusted
  rule/permissions service in this slice the caller-supplied
  ``control_metadata`` kind, rule ID/evidence and actor text cannot
  authorise an exclusion — the builder rejects every ``excluded_reviewed``
  disposition and the row stays ``blocked``/unapproved. Exclusion is never
  claimed as reviewed from caller-supplied text.
- ``blocked``: conflicting evidence, unresolved/ambiguous identity, a
  retained row with ``ingest_outcome == "conflict"`` (always), a row the
  caller cannot safely include or exclude, or a row classed as control
  metadata or of unknown kind (no authorised exclusion in this slice).
  Unknown source-row kind is never assumed to be control metadata; it may
  only end ``blocked``.

Rejections enforced by the builder: a retained row with no disposition
(omission), a row or disposition appearing twice (duplicate), a row whose
account/run/family escapes the supplied seal scope (cross-account/run), a
resolution for an observation outside the sealed run, a disposition
referencing a superseded or non-head resolution revision (stale), an
included row whose head resolution is ambiguous/unresolved or lacks a
selected occurrence, an empty or unsealed inventory (missing seal ref,
stale low high watermark, wrong row or conflict-holder count — i.e. the
snapshot was extended after the seal was taken, so a new snapshot and
operation are required), and any
payload record that does not map back to exactly one set of included
retained rows with all source-row IDs recorded. A second or conflicting
operation-to-manifest binding is rejected by
``ManifestBindingRegistry.bind`` (one operation binds exactly one
immutable manifest ID and digest; one manifest binds one operation).

Partial runs: candidate positive rows from a partial collection may be
included and linked, but completeness and currency are explicit constants:
``run_completeness_status`` and ``run_currency_status`` are always
``"unverified"`` — the caller-created seal and the supplied (possibly
truncated) snapshot cannot prove full inventory or the current head, and
neither status is upgraded without an authoritative snapshot — and
``run_coverage_status`` is the constant ``"none"``: no missing-row,
source-scope coverage, freshness or remediation claim follows from the
manifest.

Honest boundary: with the existing interfaces the exact membership of the
payload *bytes* cannot be proven (the contract binds the exact payload
SHA-256 and the payload-record-to-row mapping, but cannot authenticate the
serialization). ``payload_membership_status`` is therefore always the
explicit constant ``"pending"`` — trust is not invented. It becomes
provable only with the separate UVM membership ledger (decision
proposal step 2) plus trusted supported-API read-back; that is
intentionally out of scope here.

Synthetic-fixture scope only: pure stdlib plus the project's existing
DTOs (the supplied ``RetainedRun`` snapshot is structurally validated,
not imported from the persistence layer); no HTTP, no persistence
writes, no engine calls, no external-system evidence.

Operation binding: the ``EngineImportOperationV1`` carries only
``source_run_id`` (no account). The builder refuses a mismatched source
run, records the operation ``context_key`` verbatim, and never parses the
free-form context key as account evidence: operation-account binding is
explicitly unverified, not claimed.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
import weakref
from dataclasses import dataclass, fields
from typing import Mapping, Optional

from uvm.engine.operation import EngineImportOperationV1
from uvm.identity.model import (
    OUTCOME_MATCHED,
    OUTCOME_NEW,
    IdentityResolutionV1,
)
from uvm.identity.observations import (
    SourceObservationV1,
)

SCHEMA_VERSION = 1

# Dispositions: every retained row has exactly one.
DISPOSITION_INCLUDED = "included"
DISPOSITION_EXCLUDED_REVIEWED = "excluded_reviewed"
DISPOSITION_BLOCKED = "blocked"
_DISPOSITIONS = (
    DISPOSITION_INCLUDED,
    DISPOSITION_EXCLUDED_REVIEWED,
    DISPOSITION_BLOCKED,
)

# Source-row kinds supplied by the caller for each retained row. An unknown
# kind is never assumed to be control metadata: it may only end blocked.
ROW_KIND_CANDIDATE_POSITIVE = "candidate_positive"
ROW_KIND_CONTROL_METADATA = "control_metadata"
ROW_KIND_UNKNOWN = "unknown"
_ROW_KINDS = (
    ROW_KIND_CANDIDATE_POSITIVE,
    ROW_KIND_CONTROL_METADATA,
    ROW_KIND_UNKNOWN,
)

# The manifest never claims run coverage/remediation, whatever the run.
RUN_COVERAGE_NONE = "none"

# Exact payload-byte membership cannot be proven with the existing
# interfaces (no membership ledger, no authenticated serialization); it is
# represented explicitly as pending, never upgraded to trust.
PAYLOAD_MEMBERSHIP_PENDING = "pending"

# The caller-created seal and the supplied (possibly truncated) snapshot
# cannot prove full inventory or the current head; completeness and
# currency are explicit "unverified" constants pending an authoritative
# snapshot and are never upgraded in this slice.
RUN_COMPLETENESS_UNVERIFIED = "unverified"
RUN_CURRENCY_UNVERIFIED = "unverified"

_HEX64 = re.compile(r"[0-9a-f]{64}")
_MANIFEST_NAMESPACE = uuid.NAMESPACE_URL


class ManifestError(ValueError):
    """The supplied snapshot/dispositions/payload mapping violates the
    approved V1 manifest rule; no manifest is constructed."""


class ManifestConflictError(ManifestError):
    """A second or conflicting operation-to-manifest binding."""


def _require_uuid(value, name: str) -> None:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError):
        raise ManifestError(f"{name} must be a UVM UUID, got {value!r}") from None
    if str(parsed) != value:
        raise ManifestError(f"{name} must be a canonical UVM UUID, got {value!r}")


def _require_nonempty(value, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{name} is required")


def _require_hex64(value, name: str) -> None:
    if (not isinstance(value, str)
            or not _HEX64.fullmatch(value if isinstance(value, str) else "")):
        raise ManifestError(f"{name} must be a 64-char lowercase-hex sha256 digest")


@dataclass(frozen=True)
class InventorySealV1:
    """Seal of one bounded retained-run snapshot.

    ``retention_high_watermark`` is the maximum retention order in the
    snapshot; a concurrently extended or later-extended inventory fails
    the watermark match in the builder. ``conflict_holder_count`` is the
    number of retained rows with ``ingest_outcome == "conflict"`` — the
    seal includes all conflict holders, never a subset. ``seal_ref`` is the
    evidence reference of the sealed, consistent snapshot.
    """

    schema_version: int
    source_family: str
    source_account_id: str
    run_id: str
    retention_high_watermark: int
    retained_row_count: int
    conflict_holder_count: int
    seal_ref: str

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ManifestError(
                f"unsupported schema_version {self.schema_version!r}")
        for name in ("source_family", "source_account_id", "run_id", "seal_ref"):
            _require_nonempty(getattr(self, name), name)
        for name in ("retention_high_watermark", "retained_row_count",
                     "conflict_holder_count"):
            if (not isinstance(getattr(self, name), int)
                    or isinstance(getattr(self, name), bool)
                    or getattr(self, name) < 0):
                raise ManifestError(f"{name} must be a non-negative integer")
        if self.conflict_holder_count > self.retained_row_count:
            raise ManifestError(
                "conflict_holder_count cannot exceed retained_row_count")


@dataclass(frozen=True)
class RowDispositionV1:
    """One immutable disposition for exactly one retained row.

    ``included`` requires the safe current resolution (ID + revision of the
    head revision) and the selected occurrence. ``excluded_reviewed``
    requires the versioned source rule, evidence ref, reason and the
    authorised reviewing actor. ``blocked`` requires a reason. The
    source position is the manifest's account/run scope plus
    ``source_record_ordinal``; ``raw_evidence_sha256`` is the retained
    evidence digest of the row.
    """

    schema_version: int
    observation_id: str
    source_record_ordinal: int
    raw_evidence_sha256: str
    disposition: str
    occurrence_id: Optional[str] = None
    resolution_id: Optional[str] = None
    resolution_revision: Optional[int] = None
    exclusion_rule_id: Optional[str] = None
    exclusion_rule_version: Optional[int] = None
    exclusion_evidence_ref: Optional[str] = None
    exclusion_reason: Optional[str] = None
    exclusion_actor: Optional[str] = None
    blocked_reason: Optional[str] = None

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ManifestError(
                f"unsupported schema_version {self.schema_version!r}")
        _require_uuid(self.observation_id, "observation_id")
        if (not isinstance(self.source_record_ordinal, int)
                or isinstance(self.source_record_ordinal, bool)):
            raise ManifestError("source_record_ordinal must be an integer")
        _require_hex64(self.raw_evidence_sha256, "raw_evidence_sha256")
        if self.disposition not in _DISPOSITIONS:
            raise ManifestError(
                f"disposition must be one of {_DISPOSITIONS}, "
                f"got {self.disposition!r}")
        if self.disposition == DISPOSITION_INCLUDED:
            _require_uuid(self.occurrence_id, "occurrence_id")
            _require_uuid(self.resolution_id, "resolution_id")
            if (not isinstance(self.resolution_revision, int)
                    or isinstance(self.resolution_revision, bool)
                    or self.resolution_revision < 1):
                raise ManifestError(
                    "included disposition requires the head resolution "
                    "revision (a positive integer)")
            for name in ("exclusion_rule_id", "exclusion_rule_version",
                         "exclusion_evidence_ref", "exclusion_reason",
                         "exclusion_actor", "blocked_reason"):
                if getattr(self, name) is not None:
                    raise ManifestError(
                        f"an included disposition carries no {name}")
        elif self.disposition == DISPOSITION_EXCLUDED_REVIEWED:
            for name in ("exclusion_rule_id", "exclusion_evidence_ref",
                         "exclusion_reason", "exclusion_actor"):
                _require_nonempty(getattr(self, name), name)
            if (not isinstance(self.exclusion_rule_version, int)
                    or isinstance(self.exclusion_rule_version, bool)
                    or self.exclusion_rule_version < 1):
                raise ManifestError(
                    "excluded_reviewed requires a positive exclusion_rule_version")
            for name in ("occurrence_id", "resolution_id",
                         "resolution_revision", "blocked_reason"):
                if getattr(self, name) is not None:
                    raise ManifestError(
                        f"an excluded_reviewed disposition carries no {name}")
        else:  # blocked
            _require_nonempty(self.blocked_reason, "blocked_reason")
            for name in ("occurrence_id", "resolution_id",
                         "resolution_revision", "exclusion_rule_id",
                         "exclusion_rule_version", "exclusion_evidence_ref",
                         "exclusion_reason", "exclusion_actor"):
                if getattr(self, name) is not None:
                    raise ManifestError(
                        f"a blocked disposition carries no {name}")


@dataclass(frozen=True)
class PayloadRecordV1:
    """One import-payload record mapping back to exactly one set of
    included retained rows (a direct 1:1 record names exactly one; an
    explicit versioned transformation names every source-row ID it used).
    """

    schema_version: int
    payload_record_id: str
    source_observation_ids: tuple
    transformation_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ManifestError(
                f"unsupported schema_version {self.schema_version!r}")
        _require_nonempty(self.payload_record_id, "payload_record_id")
        if (not isinstance(self.transformation_version, int)
                or isinstance(self.transformation_version, bool)
                or self.transformation_version < 1):
            raise ManifestError(
                "transformation_version must be a positive integer")
        if (not isinstance(self.source_observation_ids, tuple)
                or not self.source_observation_ids):
            raise ManifestError(
                "source_observation_ids must be a non-empty tuple")
        for value in self.source_observation_ids:
            _require_uuid(value, "source_observation_ids")
        if len(set(self.source_observation_ids)) != len(
                self.source_observation_ids):
            raise ManifestError(
                "source_observation_ids names one row twice")


@dataclass(frozen=True)
class OccurrenceManifestV1:
    """One immutable, versioned, source-neutral manifest.

    Binds exactly one operation ID, its context and bound Test, one
    source family/account/run, one inventory seal, exactly one disposition
    per retained row, the exact payload SHA-256 and the payload-record
    mapping. ``manifest_id`` and ``manifest_sha256`` are derived
    deterministically from the canonical manifest content, so the same
    canonical content produces the same identity. Registry binding also
    checks the complete issuance-time DTO structure, including fields
    deliberately absent from the public digest. ``payload_membership_status`` is
    always the explicit ``"pending"`` constant (see module docstring), and
    ``run_coverage_status`` is always ``"none"``: the manifest never
    claims run coverage, absence or remediation, and never returns
    ``verified``. ``run_completeness_status`` and ``run_currency_status``
    are always ``"unverified"``: a caller-created seal and a supplied
    (possibly truncated) snapshot cannot prove full inventory or the
    current head.
    """

    schema_version: int
    manifest_id: str
    manifest_sha256: str
    operation_id: str
    context_key: str
    bound_test_id: Optional[str]
    source_family: str
    source_account_id: str
    run_id: str
    payload_sha256: str
    inventory_seal: InventorySealV1
    dispositions: tuple
    payload_records: tuple
    run_completeness_status: str = RUN_COMPLETENESS_UNVERIFIED
    run_currency_status: str = RUN_CURRENCY_UNVERIFIED
    run_coverage_status: str = RUN_COVERAGE_NONE
    payload_membership_status: str = PAYLOAD_MEMBERSHIP_PENDING

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ManifestError(
                f"unsupported schema_version {self.schema_version!r}")
        _require_uuid(self.manifest_id, "manifest_id")
        _require_uuid(self.operation_id, "operation_id")
        _require_nonempty(self.context_key, "context_key")
        for name in ("source_family", "source_account_id", "run_id"):
            _require_nonempty(getattr(self, name), name)
        _require_hex64(self.payload_sha256, "payload_sha256")
        _require_hex64(self.manifest_sha256, "manifest_sha256")
        if not isinstance(self.inventory_seal, InventorySealV1):
            raise ManifestError("inventory_seal must be an InventorySealV1")
        if (
            self.inventory_seal.source_family != self.source_family
            or self.inventory_seal.source_account_id
            != self.source_account_id
            or self.inventory_seal.run_id != self.run_id
        ):
            raise ManifestError(
                "inventory seal scope does not match the manifest scope")
        if not isinstance(self.dispositions, tuple):
            raise ManifestError("dispositions must be a tuple")
        for d in self.dispositions:
            if not isinstance(d, RowDispositionV1):
                raise ManifestError("dispositions must be RowDispositionV1")
        if not isinstance(self.payload_records, tuple):
            raise ManifestError("payload_records must be a tuple")
        for r in self.payload_records:
            if not isinstance(r, PayloadRecordV1):
                raise ManifestError("payload_records must be PayloadRecordV1")
        if self.run_coverage_status != RUN_COVERAGE_NONE:
            raise ManifestError(
                "run_coverage_status must be the constant 'none'; the "
                "manifest never claims run coverage")
        if self.payload_membership_status != PAYLOAD_MEMBERSHIP_PENDING:
            raise ManifestError(
                "payload_membership_status must be the explicit constant "
                "'pending'; exact payload-byte membership cannot be proven "
                "with the existing interfaces")
        if self.run_completeness_status != RUN_COMPLETENESS_UNVERIFIED:
            raise ManifestError(
                "run_completeness_status must be the explicit constant "
                "'unverified'; a caller-created seal and supplied snapshot "
                "cannot prove full inventory")
        if self.run_currency_status != RUN_CURRENCY_UNVERIFIED:
            raise ManifestError(
                "run_currency_status must be the explicit constant "
                "'unverified'; the supplied snapshot cannot prove the "
                "current head")
        digest, manifest_id = _content_digest(
            self.operation_id, self.context_key, self.bound_test_id,
            self.source_family, self.source_account_id, self.run_id,
            self.payload_sha256, self.inventory_seal, self.dispositions,
            self.payload_records)
        if digest != self.manifest_sha256 or manifest_id != self.manifest_id:
            raise ManifestError(
                "manifest content does not match its derived digest/ID; a "
                "manifest is immutable once constructed")


# In-process ledger of manifests issued by build_occurrence_manifest.
# Reviewer 425c829d (2): the registry binds only builder-issued objects.
# Membership is checked by object identity (the dataclass derives a
# field-based __eq__), so a field-identical directly constructed or
# ``replace()``d copy that passes the content digest check is still
# rejected: it bypassed the builder row checks. In-process only, matching
# the module's in-memory honesty boundary.
#
# Reviewer 90195466: the previous WeakSet keyed on the dataclass's
# field-derived hash/eq, so two distinct-but-equal builder-issued
# manifests (two independent builder calls over identical content) collapsed
# into one entry and the second's identity was lost — the registry then
# rejected the second legitimate builder-issued manifest. The ledger is
# now identity-keyed (``id`` -> weak value), so distinct equal objects each
# keep their own entry, and ``bind`` checks ``is``. The WeakValueDictionary
# cleans entries up automatically when a manifest is garbage-collected.
_BUILT_MANIFESTS: "weakref.WeakValueDictionary[int, OccurrenceManifestV1]" = (
    weakref.WeakValueDictionary())
# Frozen dataclasses can still be changed with ``object.__setattr__``.  The
# public digest deliberately omits some version/status fields, so provenance
# records every field of the manifest and its nested DTOs at issuance.  Only
# immutable built-in values and class objects enter the snapshot: it cannot
# keep the manifest alive or be changed through one of its nested objects.
_BUILT_MANIFEST_PROVENANCE: dict = {}


def _manifest_structure_snapshot(manifest: OccurrenceManifestV1) -> tuple:
    """Capture the complete DTO tree without retaining any DTO reference.

    Exact built-in types avoid invoking attacker-supplied ``__eq__`` or
    ``__repr__`` methods when comparing snapshots. Unknown/mutable values,
    extra attributes and cycles fail closed rather than being represented by
    an unreliable string or a shallow copy.
    """
    dto_types = (OccurrenceManifestV1, InventorySealV1,
                 RowDispositionV1, PayloadRecordV1)
    active: set[int] = set()

    def capture(value):
        value_type = type(value)
        if value is None or value_type in (str, int, bool):
            return value_type, value
        if value_type is tuple or value_type in dto_types:
            key = id(value)
            if key in active:
                raise ManifestError("manifest structure contains a cycle")
            active.add(key)
            try:
                if value_type is tuple:
                    return tuple, tuple(capture(item) for item in value)
                names = tuple(field.name for field in fields(value_type))
                attributes = vars(value)
                if (type(attributes) is not dict
                        or set(attributes) != set(names)):
                    raise ManifestError(
                        "manifest structure has missing or extra DTO fields")
                return value_type, tuple(
                    (name, capture(getattr(value, name))) for name in names)
            finally:
                active.remove(key)
        raise ManifestError("manifest structure contains an unsupported value")

    try:
        return capture(manifest)
    except (AttributeError, RecursionError, TypeError) as exc:
        raise ManifestError("manifest structure cannot be captured") from exc


def _record_built_manifest(manifest: OccurrenceManifestV1) -> None:
    key = id(manifest)
    snapshot = _manifest_structure_snapshot(manifest)

    def remove(ref, *, key=key):
        entry = _BUILT_MANIFEST_PROVENANCE.get(key)
        if entry is not None and entry[0] is ref:
            _BUILT_MANIFEST_PROVENANCE.pop(key, None)

    _BUILT_MANIFEST_PROVENANCE[key] = (
        weakref.ref(manifest, remove),
        snapshot,
    )


def _content_digest(
    operation_id: str, context_key: str, bound_test_id: Optional[str],
    source_family: str, source_account_id: str, run_id: str,
    payload_sha256: str, seal: InventorySealV1,
    dispositions: tuple, payload_records: tuple,
) -> tuple:
    """The canonical content and its derived (ID, SHA-256) pair."""
    seal_payload = {
        "source_family": seal.source_family,
        "source_account_id": seal.source_account_id,
        "run_id": seal.run_id,
        "retention_high_watermark": seal.retention_high_watermark,
        "retained_row_count": seal.retained_row_count,
        "conflict_holder_count": seal.conflict_holder_count,
        "seal_ref": seal.seal_ref,
    }
    disposition_payload = sorted(
        (
            {
                "observation_id": d.observation_id,
                "source_record_ordinal": d.source_record_ordinal,
                "raw_evidence_sha256": d.raw_evidence_sha256,
                "disposition": d.disposition,
                "occurrence_id": d.occurrence_id,
                "resolution_id": d.resolution_id,
                "resolution_revision": d.resolution_revision,
                "exclusion_rule_id": d.exclusion_rule_id,
                "exclusion_rule_version": d.exclusion_rule_version,
                "exclusion_evidence_ref": d.exclusion_evidence_ref,
                "exclusion_reason": d.exclusion_reason,
                "exclusion_actor": d.exclusion_actor,
                "blocked_reason": d.blocked_reason,
            }
            for d in dispositions
        ),
        key=lambda item: item["observation_id"],
    )
    record_payload = sorted(
        (
            {
                "payload_record_id": r.payload_record_id,
                "source_observation_ids": list(r.source_observation_ids),
                "transformation_version": r.transformation_version,
            }
            for r in payload_records
        ),
        key=lambda item: item["payload_record_id"],
    )
    canonical = json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "operation_id": operation_id,
            "context_key": context_key,
            "bound_test_id": bound_test_id,
            "source_family": source_family,
            "source_account_id": source_account_id,
            "run_id": run_id,
            "payload_sha256": payload_sha256,
            "inventory_seal": seal_payload,
            "dispositions": disposition_payload,
            "payload_records": record_payload,
            "run_completeness_status": RUN_COMPLETENESS_UNVERIFIED,
            "run_currency_status": RUN_CURRENCY_UNVERIFIED,
            "run_coverage_status": RUN_COVERAGE_NONE,
            "payload_membership_status": PAYLOAD_MEMBERSHIP_PENDING,
        },
        sort_keys=True, separators=(",", ":"), allow_nan=False,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    manifest_id = str(
        uuid.uuid5(_MANIFEST_NAMESPACE,
                   f"uvm:occurrence-manifest:v1:{canonical}"))
    return digest, manifest_id


def _require_retained_run(retained) -> None:
    """Structural validation of the supplied ``RetainedRun`` snapshot
    (``uvm.persistence.observation_store.RetainedRun``): the persistence
    module is not imported here, so the snapshot is validated by shape."""
    for name in ("source_account_id", "run_id", "rows", "quarantine"):
        if not hasattr(retained, name):
            raise ManifestError(
                f"supplied snapshot is missing {name!r}; it must be a "
                "RetainedRun")
    if (not isinstance(retained.source_account_id, str)
            or not retained.source_account_id):
        raise ManifestError("snapshot source_account_id must be a non-empty string")
    if (not isinstance(retained.run_id, str) or not retained.run_id):
        raise ManifestError("snapshot run_id must be a non-empty string")
    if not isinstance(retained.rows, (tuple, list)):
        raise ManifestError("snapshot rows must be a tuple")


def _require_retained_row(r) -> None:
    """Structural validation of one supplied ``RetainedObservation``."""
    for name in ("observation", "retention_order", "ingest_outcome"):
        if not hasattr(r, name):
            raise ManifestError(
                f"supplied retained row is missing {name!r}; it must be a "
                "RetainedObservation")
    if not isinstance(r.observation, SourceObservationV1):
        raise ManifestError("retained row must hold a SourceObservationV1")
    if (not isinstance(r.retention_order, int)
            or isinstance(r.retention_order, bool) or r.retention_order < 0):
        raise ManifestError("retained row retention_order must be a non-negative integer")
    if r.ingest_outcome not in ("created", "conflict"):
        raise ManifestError(
            f"retained row {r.observation.observation_id} has unknown "
            f"ingest outcome {r.ingest_outcome!r}")


def _validate_resolution_history(
    observation_id: str, history: tuple
) -> IdentityResolutionV1:
    """Validate the supplied append-only history and return the head."""
    if not history:
        raise ManifestError(f"no resolution history supplied for {observation_id}")
    for entry in history:
        if not isinstance(entry, IdentityResolutionV1):
            raise ManifestError(
                f"resolution history for {observation_id} must contain "
                "IdentityResolutionV1 records")
        if entry.observation_id != observation_id:
            raise ManifestError(
                f"resolution {entry.resolution_id} belongs to observation "
                f"{entry.observation_id}, not {observation_id}")
    for index, entry in enumerate(history):
        if entry.revision != index + 1:
            raise ManifestError(
                f"resolution history for {observation_id} is not contiguous "
                f"at revision {entry.revision} (expected {index + 1})")
        expected = None if index == 0 else history[index - 1].resolution_id
        if entry.supersedes_resolution_id != expected:
            raise ManifestError(
                f"resolution {entry.resolution_id} does not supersede the "
                "immediate prior observation history")
    return history[-1]


def build_occurrence_manifest(
    *,
    operation: EngineImportOperationV1,
    retained,
    seal: InventorySealV1,
    resolutions: Mapping[str, tuple],
    dispositions,
    payload_records,
    row_kinds: Mapping[str, str],
) -> OccurrenceManifestV1:
    """Build and validate one immutable ``OccurrenceManifestV1``.

    ``retained`` is the complete supplied ``RetainedRun`` snapshot
    (structurally validated); ``seal`` is the ``InventorySealV1`` of the
    sealed snapshot, which the builder verifies against the supplied rows
    (scope, row count, retention high watermark and conflict-holder count);
    ``resolutions`` maps observation ID to its append-only resolution
    history (only for observations of this run); ``dispositions`` is one
    ``RowDispositionV1`` per retained row, exactly once; ``payload_records``
    is the payload-construction mapping; ``row_kinds`` classifies each
    retained row (a missing entry is ``unknown``). Raises
    ``ManifestError`` on any rule violation; nothing partial is returned.
    """
    if not isinstance(operation, EngineImportOperationV1):
        raise ManifestError("operation must be an EngineImportOperationV1")
    _require_retained_run(retained)
    if not isinstance(seal, InventorySealV1):
        raise ManifestError("seal must be an InventorySealV1")

    rows: tuple = tuple(retained.rows)
    if not rows:
        raise ManifestError(
            "empty inventory: an empty or unsealed retained-run inventory "
            "cannot pass operation-wide payload-link proof")

    scope = (retained.source_account_id, retained.run_id)

    # -- every retained row: shape, scope, duplicates -----------------------
    seen_ids: set = set()
    for r in rows:
        _require_retained_row(r)
        obs = r.observation
        if (obs.source_account_id, obs.run_id) != scope:
            raise ManifestError(
                f"retained row {obs.observation_id} escapes the sealed "
                "account/run scope (cross-account/run row)")
        if r.observation.observation_id in seen_ids:
            raise ManifestError(
                f"retained row {r.observation.observation_id} appears twice "
                "in the snapshot")
        seen_ids.add(r.observation.observation_id)
    row_ids = seen_ids

    families = {r.observation.source_family for r in rows}
    if len(families) != 1:
        raise ManifestError(
            f"retained rows span multiple source families {sorted(families)}")
    source_family = families.pop()

    # -- seal: unsealed or concurrently extended inventories ---------------
    max_watermark = max(r.retention_order for r in rows)
    conflict_holders = sum(1 for r in rows if r.ingest_outcome == "conflict")
    if (
        seal.source_family != source_family
        or seal.source_account_id != scope[0]
        or seal.run_id != scope[1]
    ):
        raise ManifestError(
            "seal scope does not match the sealed account/run/family of "
            "the supplied snapshot")
    if seal.retained_row_count != len(rows):
        raise ManifestError(
            f"seal records {seal.retained_row_count} retained rows but the "
            f"snapshot has {len(rows)}; the snapshot and its seal are not "
            "the same consistent snapshot")
    if seal.retention_high_watermark != max_watermark:
        raise ManifestError(
            f"seal retention high watermark {seal.retention_high_watermark} "
            f"does not match the snapshot's {max_watermark}; the inventory "
            "was extended after the seal was taken (or the seal is stale) "
            "— a new snapshot and operation are required")
    if seal.conflict_holder_count != conflict_holders:
        raise ManifestError(
            f"seal records {seal.conflict_holder_count} conflict holders "
            f"but the snapshot has {conflict_holders}; the seal must "
            "include all conflict holders")

    # -- dispositions: exactly one per retained row, exactly all -----------
    dispositions = tuple(dispositions)
    if any(not isinstance(d, RowDispositionV1) for d in dispositions):
        raise ManifestError("dispositions must be RowDispositionV1")
    # Reviewer 425c829d (1): materialise the payload_records iterable
    # exactly once BEFORE the type check and mapping validation. The
    # previous check ran over the raw iterable first; for a generator it
    # consumed every valid record, the later tuple() then saw nothing, and
    # the record escaped the mapping validation that tuple input never
    # could. Tuple and generator input are now rejected identically.
    try:
        payload_records = tuple(payload_records)
    except TypeError:
        raise ManifestError(
            "payload_records must be an iterable of PayloadRecordV1") \
            from None
    if any(not isinstance(r, PayloadRecordV1) for r in payload_records):
        raise ManifestError("payload_records must be PayloadRecordV1")

    disp_ids = [d.observation_id for d in dispositions]
    if len(set(disp_ids)) != len(disp_ids):
        raise ManifestError(
            "a retained row has more than one disposition; every retained "
            "row has exactly one")
    if set(disp_ids) != row_ids:
        missing = row_ids - set(disp_ids)
        extra = set(disp_ids) - row_ids
        if missing:
            raise ManifestError(
                f"retained row(s) {sorted(missing)} have no disposition; "
                "omitted rows cannot disappear from proof")
        raise ManifestError(
            f"disposition(s) {sorted(extra)} reference observation(s) "
            "outside the sealed run")
    by_obs = {r.observation.observation_id: r for r in rows}
    for d in dispositions:
        row = by_obs[d.observation_id]
        obs = row.observation
        if d.source_record_ordinal != obs.source_record_ordinal:
            raise ManifestError(
                f"disposition for {d.observation_id} names the wrong source "
                f"position {d.source_record_ordinal} "
                f"(retained: {obs.source_record_ordinal})")
        if d.raw_evidence_sha256 != obs.raw_evidence_sha256:
            raise ManifestError(
                f"disposition for {d.observation_id} does not match the "
                "retained evidence digest")
        kind = row_kinds.get(d.observation_id, ROW_KIND_UNKNOWN)
        if kind not in _ROW_KINDS:
            raise ManifestError(
                f"unknown row kind {kind!r} for {d.observation_id}")
        # Reviewer 676b37df (1): a retained row with
        # ingest_outcome == "conflict" is always blocked — it cannot be
        # included or excluded, even with a supplied matched resolution.
        if row.ingest_outcome == "conflict" \
                and d.disposition != DISPOSITION_BLOCKED:
            raise ManifestError(
                f"retained conflict holder {d.observation_id} must be "
                "blocked: a retained row with ingest_outcome='conflict' "
                "cannot be included or excluded, even with a supplied "
                "matched resolution")
        # Reviewer 676b37df (2): without a trusted rule/permissions
        # service in this slice, caller-supplied control_metadata kind,
        # rule ID/evidence and actor text cannot authorise an exclusion.
        # excluded_reviewed is unapproved; the row stays blocked.
        if d.disposition == DISPOSITION_EXCLUDED_REVIEWED:
            raise ManifestError(
                f"excluded_reviewed is unapproved in this slice: a "
                "trusted rule/permissions service must authorise an "
                f"exclusion; caller-supplied control_metadata kind, rule "
                f"ID/evidence and actor text are not evidence — row "
                f"{d.observation_id} stays blocked/unapproved")
        # Unknown kinds and caller-classed control metadata are never
        # assumed includable: with no authorised exclusion in this slice
        # they may only end blocked.
        if kind == ROW_KIND_UNKNOWN and d.disposition != DISPOSITION_BLOCKED:
            raise ManifestError(
                f"row {d.observation_id} has an unknown row kind; it may "
                "only be blocked, never assumed to be control metadata "
                "or included as proven")
        if kind == ROW_KIND_CONTROL_METADATA \
                and d.disposition != DISPOSITION_BLOCKED:
            raise ManifestError(
                f"row {d.observation_id} is classed as control metadata; "
                "with no authorised exclusion in this slice it may only "
                "be blocked")

    # -- resolution history: selected rows only, current revisions --------
    for observation_id, history in resolutions.items():
        if observation_id not in row_ids:
            raise ManifestError(
                f"resolution history supplied for observation "
                f"{observation_id} outside the sealed run")
    for d in dispositions:
        if d.disposition != DISPOSITION_INCLUDED:
            continue
        history = resolutions.get(d.observation_id)
        if history is None:
            raise ManifestError(
                f"row {d.observation_id} is included but has no resolution "
                "history; an included row needs a safe current resolution")
        head = _validate_resolution_history(d.observation_id, tuple(history))
        if d.resolution_id != head.resolution_id or (
                d.resolution_revision != head.revision):
            raise ManifestError(
                f"row {d.observation_id} is included under stale/superseded "
                f"resolution {d.resolution_id} r{d.resolution_revision}; "
                f"the current head is {head.resolution_id} "
                f"r{head.revision}")
        if head.outcome not in (OUTCOME_MATCHED, OUTCOME_NEW):
            raise ManifestError(
                f"row {d.observation_id} cannot be included: the current "
                f"resolution outcome is {head.outcome!r}; conflicting "
                "evidence or unresolved/ambiguous identity stays blocked")
        if d.occurrence_id != head.occurrence_id:
            raise ManifestError(
                f"row {d.observation_id} names occurrence {d.occurrence_id} "
                f"but the current resolution selected "
                f"{head.occurrence_id!r}")

    # -- payload mapping: every record back to included rows, exactly once -
    seen_records = set()
    covered: set = set()
    disp_by_obs = {d.observation_id: d for d in dispositions}
    for r in payload_records:
        if r.payload_record_id in seen_records:
            raise ManifestError(
                f"payload record {r.payload_record_id} appears twice")
        seen_records.add(r.payload_record_id)
        for observation_id in r.source_observation_ids:
            disp = disp_by_obs.get(observation_id)
            if disp is None:
                raise ManifestError(
                    f"payload record {r.payload_record_id} maps to "
                    f"observation {observation_id} which is not a "
                    "retained row of the sealed run; payload records map "
                    "back to retained rows only")
            if disp.disposition != DISPOSITION_INCLUDED:
                raise ManifestError(
                    f"payload record {r.payload_record_id} maps to row "
                    f"{observation_id} which is {disp.disposition!r}; "
                    "payload records map back to included rows only")
            if observation_id in covered:
                raise ManifestError(
                    f"row {observation_id} is mapped by more than one "
                    "payload record; every included row maps back to "
                    "exactly one record (or one versioned transformation)")
            covered.add(observation_id)
    included_ids = {d.observation_id for d in dispositions
                    if d.disposition == DISPOSITION_INCLUDED}
    uncovered = included_ids - covered
    if uncovered:
        raise ManifestError(
            f"included row(s) {sorted(uncovered)} have no payload record; "
            "every included row must map to exactly one payload record")

    # -- operation binding: exact run only; the operation carries no ----
    # -- account, and its context_key is never parsed as account evidence
    if operation.source_run_id != scope[1]:
        raise ManifestError(
            f"operation {operation.operation_id} carries source_run_id "
            f"{operation.source_run_id!r}, not the sealed run {scope[1]!r}; "
            "the operation carries only source_run_id (no account) and its "
            "context_key is not parsed as evidence — operation-account "
            "binding is unverified")
    # The request Test is immutable pre-POST input for a reimport.  The
    # operation's ``bound_test_id`` is deliberately a post-POST result and
    # must remain null on both first imports and pending reimports.
    manifest_test_id = (operation.test_id
                        if operation.request_kind == "reimport" else None)
    digest, manifest_id = _content_digest(
        operation.operation_id, operation.context_key,
        manifest_test_id, source_family, scope[0], scope[1],
        operation.payload_sha256, seal, dispositions, payload_records)
    manifest = OccurrenceManifestV1(
        SCHEMA_VERSION, manifest_id, digest,
        operation.operation_id, operation.context_key,
        manifest_test_id, source_family, scope[0], scope[1],
        operation.payload_sha256, seal, dispositions, payload_records)
    # Reviewer 425c829d (2): the builder is the only normal construction
    # path; issue the manifest into the builder ledger so the registry
    # can refuse directly constructed bypasses. Identity-keyed so two
    # distinct-but-equal builder-issued manifests each stay tracked
    # (Reviewer 90195466).
    _BUILT_MANIFESTS[id(manifest)] = manifest
    _record_built_manifest(manifest)
    return manifest


__all__ = [
    "SCHEMA_VERSION",
    "DISPOSITION_INCLUDED",
    "DISPOSITION_EXCLUDED_REVIEWED",
    "DISPOSITION_BLOCKED",
    "ROW_KIND_CANDIDATE_POSITIVE",
    "ROW_KIND_CONTROL_METADATA",
    "ROW_KIND_UNKNOWN",
    "RUN_COVERAGE_NONE",
    "RUN_COMPLETENESS_UNVERIFIED",
    "RUN_CURRENCY_UNVERIFIED",
    "PAYLOAD_MEMBERSHIP_PENDING",
    "ManifestError",
    "ManifestConflictError",
    "InventorySealV1",
    "RowDispositionV1",
    "PayloadRecordV1",
    "OccurrenceManifestV1",
    "ManifestBindingResult",
    "ManifestBindingRegistry",
    "build_occurrence_manifest",
]


@dataclass(frozen=True)
class ManifestBindingResult:
    """Outcome of a registry binding command.

    ``outcome`` is one of ``bound`` | ``duplicate`` | ``conflict``;
    ``manifest`` is the bound manifest, ``conflict_with`` the manifest ID
    the binding collided with.
    """

    outcome: str
    manifest: Optional[OccurrenceManifestV1]
    reason: Optional[str] = None
    conflict_with: Optional[str] = None


class ManifestBindingRegistry:
    """In-memory operation-to-manifest binding: one operation binds exactly
    one immutable manifest ID and digest; one manifest binds exactly one
    operation. A second or conflicting binding is rejected (``conflict``),
    never silently replaced; replaying the identical binding is idempotent
    (``duplicate``). In-memory only: nothing here is durable persistence.
    """

    def __init__(self) -> None:
        self._by_operation: dict = {}
        self._by_manifest: dict = {}

    # -- queries -----------------------------------------------------------

    def for_operation(self, operation_id: str) -> Optional[OccurrenceManifestV1]:
        entry = self._by_operation.get(operation_id)
        return entry[1] if entry is not None else None

    def for_manifest(self, manifest_id: str) -> Optional[OccurrenceManifestV1]:
        entry = self._by_manifest.get(manifest_id)
        return entry[1] if entry is not None else None

    def _bind_verified_durable(self, manifest: OccurrenceManifestV1) -> None:
        """Bind a manifest already revalidated by the durable operation store.

        Persisted manifests cannot retain this process's weak builder-issued
        marker. This private path is only for replaying evidence after the
        owning store has validated the persisted manifest ledger.
        """
        if not isinstance(manifest, OccurrenceManifestV1):
            raise ManifestError("durable replay requires OccurrenceManifestV1")
        self._by_operation[manifest.operation_id] = (
            manifest.manifest_sha256, manifest)
        self._by_manifest[manifest.manifest_id] = (
            manifest.manifest_sha256, manifest)

    # -- commands ----------------------------------------------------------

    def bind(
        self, manifest: OccurrenceManifestV1
    ) -> ManifestBindingResult:
        if not isinstance(manifest, OccurrenceManifestV1):
            raise ManifestError("manifest must be an OccurrenceManifestV1")
        # Reviewer 425c829d (2): a directly constructed
        # OccurrenceManifestV1 passes the content digest check but bypasses
        # the builder row checks (conflict holders, unapproved exclusions,
        # unknown kinds, mapping rules); only builder-issued objects bind.
        # Reviewer 90195466: identity-keyed ledger — check ``is`` against the
        # weakly tracked values so distinct equal builder-issued manifests
        # are each recognised, not collapsed.
        if not any(built is manifest
                   for built in _BUILT_MANIFESTS.values()):
            raise ManifestError(
                "registry binding accepts only manifests constructed by "
                "build_occurrence_manifest; a directly constructed "
                "OccurrenceManifestV1 bypasses the builder row checks and "
                "cannot be bound")
        provenance = _BUILT_MANIFEST_PROVENANCE.get(id(manifest))
        if provenance is None or provenance[0]() is not manifest:
            raise ManifestError(
                "registry binding cannot establish issuance provenance for "
                "this manifest")
        if _manifest_structure_snapshot(manifest) != provenance[1]:
            raise ManifestError(
                "builder-issued manifest structure changed after issuance")
        try:
            current_digest, current_id = _content_digest(
                manifest.operation_id, manifest.context_key,
                manifest.bound_test_id, manifest.source_family,
                manifest.source_account_id, manifest.run_id,
                manifest.payload_sha256, manifest.inventory_seal,
                manifest.dispositions, manifest.payload_records)
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise ManifestError(
                "builder-issued manifest content cannot be revalidated") \
                from exc
        if (manifest.manifest_sha256, manifest.manifest_id) != (
                current_digest, current_id):
            raise ManifestError(
                "builder-issued manifest content changed after issuance; "
                "recomputed public digest/ID cannot establish provenance")
        op_entry = self._by_operation.get(manifest.operation_id)
        man_entry = self._by_manifest.get(manifest.manifest_id)
        if op_entry is not None:
            if op_entry[0] == manifest.manifest_sha256:
                return ManifestBindingResult(
                    "duplicate", op_entry[1],
                    reason="identical operation-to-manifest binding already "
                           "bound")
            raise ManifestConflictError(
                f"operation {manifest.operation_id} is already bound to "
                f"manifest {op_entry[1].manifest_id}; a second or "
                "conflicting operation-to-manifest binding is rejected")
        if man_entry is not None:
            raise ManifestConflictError(
                f"manifest {manifest.manifest_id} is already bound to "
                f"operation {man_entry[1].operation_id}; a manifest binds "
                "exactly one operation")
        self._by_operation[manifest.operation_id] = (
            manifest.manifest_sha256, manifest)
        self._by_manifest[manifest.manifest_id] = (
            manifest.manifest_sha256, manifest)
        return ManifestBindingResult("bound", manifest)
