"""UVM identity contracts, version 1 (G1 slice, CR-02/03/04, FR-ID-01/02).

Pure Python, in-memory, no persistence or engine calls. Contracts follow
openspec/changes/g1-engine-identity-contracts/design.md (G1 design approved at
commit b9b1c63f): native groups keyed by namespaced source-native identifiers
with CVEs as many-to-many references, retained source observations, an
evidence-based resolver with matched/new/ambiguous/unresolved outcomes,
stable exposure across verified rebuilds with distinct incarnations and
occurrences, and safe idempotency/conflict semantics for source rows.

Synthetic-fixture scope only: nothing here is integration or external-system
evidence.
"""

from uvm.identity.observations import (
    SCHEMA_VERSION,
    MISSING_NOT_APPLICABLE,
    MISSING_NOT_SUPPLIED,
    MISSING_UNVERIFIED,
    MissingField,
    SourceObservationV1,
    IngestResult,
    ObservationStore,
)
from uvm.identity.model import (
    NativeGroupKey,
    Group,
    Workload,
    Incarnation,
    Exposure,
    Occurrence,
    IdentityResolutionV1,
    IdentityResolutionV2,
    SCHEMA_VERSION_V2,
    CorrectionRecord,
    IdentityState,
)
from uvm.identity.resolver import RuleV1, resolve

__all__ = [
    "SCHEMA_VERSION",
    "MISSING_NOT_SUPPLIED",
    "MISSING_NOT_APPLICABLE",
    "MISSING_UNVERIFIED",
    "MissingField",
    "SourceObservationV1",
    "IngestResult",
    "ObservationStore",
    "NativeGroupKey",
    "Group",
    "Workload",
    "Incarnation",
    "Exposure",
    "Occurrence",
    "IdentityResolutionV1",
    "IdentityResolutionV2",
    "SCHEMA_VERSION_V2",
    "CorrectionRecord",
    "IdentityState",
    "RuleV1",
    "resolve",
]
