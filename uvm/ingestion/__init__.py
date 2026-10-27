"""Source-neutral collection contracts (G2, synthetic/in-memory only)."""

from .run import (
    CollectionRunV1,
    CollectionScheduleV1,
    ExpectedRunV1,
    AttemptFact,
    PageFact,
    ExpectedRowV1,
    SyntheticExpectedCohortV1,
    SyntheticFreshnessRuleV1,
    QualityResult,
    QualityEvaluation,
    PageReplayResult,
    RETRIEVAL_COMPLETE,
    RETRIEVAL_PARTIAL,
    RETRIEVAL_FAILED,
    COVERAGE_COMPLETE,
    COVERAGE_PARTIAL,
    COVERAGE_UNKNOWN,
    FRESHNESS_FRESH,
    FRESHNESS_STALE,
    FRESHNESS_UNKNOWN,
)

__all__ = [name for name in globals() if not name.startswith("_")]
