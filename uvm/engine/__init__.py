"""UVM engine (DefectDojo CE) contracts, version 1 (G1 slice, CR-01/03/04).

Pure Python, in-memory, no HTTP, no persistence, no engine calls. The
contract follows
openspec/changes/g1-engine-identity-contracts/design.md (the
``EngineImportOperationV1`` row): one operation per intended context and
retained payload with the full pre-POST context and payload digest
recorded, explicit ``close_old_findings=False``, per-context
serialisation, a single POST per operation+payload with reconciliation
before any retry, and settle only from completed deduplication plus a
matching supported-API Test/Finding read-back. Engine Finding/endpoint
counts are measured outputs, never inferred UVM occurrence counts.

Synthetic-fixture scope only: nothing here is integration or external-system
evidence.
"""

from uvm.engine.operation import (
    SCHEMA_VERSION,
    STATUS_PENDING,
    STATUS_SETTLED,
    STATUS_FAILED,
    STATUS_QUARANTINED,
    STATUS_CONFLICT,
    REQUEST_IMPORT,
    REQUEST_REIMPORT,
    EngineImportOperationV1,
    OperationResult,
    OperationStore,
)

__all__ = [
    "SCHEMA_VERSION",
    "STATUS_PENDING",
    "STATUS_SETTLED",
    "STATUS_FAILED",
    "STATUS_QUARANTINED",
    "STATUS_CONFLICT",
    "REQUEST_IMPORT",
    "REQUEST_REIMPORT",
    "EngineImportOperationV1",
    "OperationResult",
    "OperationStore",
]
