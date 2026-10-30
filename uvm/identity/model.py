"""UVM identity records and state (G1 slice, version 1).

Native groups are keyed by ``(source family, identifier scheme, authority
namespace, native identifier)``; CVEs are many-to-many references that never
merge groups (CR-02). An exposure links a native group to a logical workload
and survives verified rebuilds; incarnations and occurrences are distinct per
replacement and per remediable instance/component portion (CR-03/CR-04).
Resolution records are append-only, rule-versioned evidence (FR-ID-01/02).
"""

from __future__ import annotations

import json
import math
import types
import uuid
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from typing import Mapping, Optional, cast

from uvm.identity.observations import SCHEMA_VERSION, SourceObservationV1, _require_uuid


def new_id() -> str:
    """Stable UVM UUID (immutable once assigned). The approved G1 Version 1
    contracts make every UVM ID an immutable UUID, so generated IDs are
    bare canonical UUID strings with no prefix."""
    return str(uuid.uuid4())


@dataclass(frozen=True)
class NativeGroupKey:
    """Group key per the approved G1 design. Account-local identifiers carry
    their authority account in ``native_id_authority``; globally meaningful
    identifiers (e.g. Qualys QID) share one namespace across accounts."""

    source_family: str
    native_id_scheme: str
    native_id_authority: str
    native_id_value: str


@dataclass
class Group:
    group_id: str
    key: NativeGroupKey
    cve_refs: set[str] = field(default_factory=set)
    revision: int = 1
    created_at: datetime = None  # type: ignore[assignment]


@dataclass
class Workload:
    """Logical workload. ``stable_attrs`` are the attributes the resolver may
    match on; which of them may *prove* correspondence is decided by the
    rule (``RuleV1.workload_match_fields``). IP, ephemeral hostname, instance
    ID, image digest or component version alone never prove it."""

    workload_id: str
    stable_attrs: dict[str, str]
    revision: int = 1
    created_at: datetime = None  # type: ignore[assignment]


@dataclass
class Incarnation:
    """One concrete instantiation of a workload (a host). Replacement hosts
    get a new incarnation; same-role replicas are distinct incarnations."""

    incarnation_id: str
    workload_id: str
    host_locator: Optional[str]
    image_ref: Optional[str]
    # None means unknown; never the collection time.
    first_observed_at: Optional[datetime]
    revision: int = 1
    created_at: datetime = None  # type: ignore[assignment]


@dataclass
class Exposure:
    """A native group exposed on a logical workload. Stable across verified
    rebuilds: the exposure ID and earliest supported detection are retained
    while incarnations/occurrences are replaced."""

    exposure_id: str
    group_id: str
    workload_id: str
    # Earliest supported detection; retained on succession, never reset.
    first_observed_at: Optional[datetime]
    revision: int = 1
    created_at: datetime = None  # type: ignore[assignment]


@dataclass
class Occurrence:
    """One independently remediable instance/component portion of an
    exposure. Keyed per (exposure, incarnation, component); completing one
    portion never completes another (CR-04)."""

    occurrence_id: str
    exposure_id: str
    incarnation_id: str
    component_locator: Optional[str]
    # None means unknown observation time; never the collection time.
    first_observed_at: Optional[datetime]
    first_ingested_at: datetime
    revision: int = 1
    created_at: datetime = None  # type: ignore[assignment]


@dataclass(frozen=True)
class IdentityResolutionV1:
    """Append-only, rule-versioned resolution record (FR-ID-01).

    ``matched`` or ``new`` names exactly one group, workload, incarnation,
    exposure and occurrence. ``ambiguous`` names at least two candidate
    explanations and no selected workload/exposure. ``unresolved`` names no
    safe match. No outcome merges, completes or discards evidence.
    """

    schema_version: int
    resolution_id: str
    revision: int
    observation_id: str
    rule_id: str
    rule_version: int
    matching_inputs: dict[str, str]
    candidate_workload_ids: tuple[str, ...]
    outcome: str
    evaluated_at: datetime
    group_id: Optional[str] = None
    workload_id: Optional[str] = None
    incarnation_id: Optional[str] = None
    exposure_id: Optional[str] = None
    occurrence_id: Optional[str] = None
    candidate_explanations: tuple[dict, ...] = ()
    reason: Optional[str] = None
    supersedes_resolution_id: Optional[str] = None

    def __post_init__(self) -> None:
        # Every UVM identity record ID is an immutable UUID (approved G1
        # Version 1 shared contracts); validate on construction.
        _require_uuid(self.resolution_id, "resolution_id")
        _require_uuid(self.observation_id, "observation_id")
        for value in self.candidate_workload_ids:
            _require_uuid(value, "candidate_workload_ids")
        for name in ("group_id", "workload_id", "incarnation_id",
                     "exposure_id", "occurrence_id", "supersedes_resolution_id"):
            value = getattr(self, name)
            if value is not None:
                _require_uuid(value, name)


OUTCOME_MATCHED = "matched"
OUTCOME_NEW = "new"
OUTCOME_AMBIGUOUS = "ambiguous"
OUTCOME_UNRESOLVED = "unresolved"
OUTCOMES = (OUTCOME_MATCHED, OUTCOME_NEW, OUTCOME_AMBIGUOUS, OUTCOME_UNRESOLVED)

# Stored schema version for V2 resolution rows (approved revision-anchor
# amendment, d5fe24d). The V1 contract and its existing SCHEMA_VERSION=1 are
# untouched.
SCHEMA_VERSION_V2 = 2


def _require_positive_revision(value, name: str) -> None:
    """A V2 selection anchor names the record's revision at the captured
    point. A revision is a positive integer: booleans, zero, negatives and
    non-integers are never anchors."""
    if type(value) is not int or value < 1:
        raise ValueError(f"{name} must be a positive integer revision, got {value!r}")


def _require_v2_uuid(value: object, name: str) -> None:
    """Keep V2 identifiers canonical, immutable strings without changing V1."""
    if type(value) is not str:
        raise ValueError(f"{name} must be a canonical UVM UUID string")
    _require_uuid(value, name)


def _copy_json_evidence(value: object, name: str, *, immutable: bool) -> object:
    """Copy JSON-like evidence at every depth, rejecting cycles and unknown types.

    ``immutable`` turns objects into mapping proxies and arrays into tuples;
    the reverse yields fresh plain dicts/lists for persistence. The explicit
    stack also handles evidence deeper than Python's recursion limit.
    """
    result: list[object] = [None]
    # (finishing, source, parent, slot, path, destination)
    stack: list[tuple[bool, object, object, object, str, object]] = [
        (False, value, result, 0, name, None)
    ]
    active: set[int] = set()
    while stack:
        finishing, source, parent, slot, path, destination = stack.pop()
        if finishing:
            active.remove(id(source))
            if immutable:
                parent[slot] = (types.MappingProxyType(destination)
                                if type(destination) is dict else tuple(destination))
            else:
                parent[slot] = destination
            continue

        if source is None or type(source) in (str, int, bool):
            parent[slot] = source
            continue
        if type(source) is float:
            if not math.isfinite(source):
                raise ValueError(f"{path} must contain only finite JSON numbers")
            parent[slot] = source
            continue

        if type(source) in (dict, types.MappingProxyType):
            entries = list(source.items())
            for key, _ in entries:
                if type(key) is not str:
                    raise ValueError(f"{path} must contain only string object keys")
            destination = {}
        elif type(source) in (list, tuple):
            entries = list(enumerate(source))
            destination = [None] * len(entries)
        else:
            raise ValueError(f"{path} has unsupported evidence type {type(source).__name__}")

        if id(source) in active:
            raise ValueError(f"{path} contains a cycle")
        active.add(id(source))
        stack.append((True, source, parent, slot, path, destination))
        for key, child in reversed(entries):
            stack.append((False, child, destination, key,
                          f"{path}[{key!r}]", None))
    return result[0]


@dataclass(frozen=True)
class IdentityResolutionV2:
    """Append-only, rule-versioned V2 resolution record (FR-ID-01/02, CR-03;
    approved revision-anchor amendment, decision recorded at d5fe24d).

    Carries the V1 fields and adds ``selected_exposure_revision`` and
    ``selected_occurrence_revision``. For ``matched`` or ``new`` both anchors
    are positive integers tied to the selected exposure and occurrence, and
    identify the exact revision of each record at selection — not
    interchangeable counters. ``ambiguous`` may retain a known native group
    but selects no workload membership; ``unresolved`` has no group or
    membership. Both carry no anchors (both null); their temporal-selection
    status ``not_applicable`` is derived by the later reader, not persisted
    as a fabricated status here. This DTO alone makes no verified temporal
    claim; it is not used by any writer until the additive 0003 schema and
    the guarded selection writer exist. V1 rows are never rewritten into
    this shape.

    ``matching_inputs`` and ``candidate_explanations`` are deep immutable
    snapshots of JSON-like evidence. ``to_primitives()`` returns an independent
    JSON-ready dict for a later writer: arrays become lists and ``evaluated_at``
    becomes an ISO 8601 string. A reader must parse that string back to a
    datetime before constructing this DTO. This method does not write a row.
    """

    schema_version: int
    resolution_id: str
    revision: int
    observation_id: str
    rule_id: str
    rule_version: int
    matching_inputs: Mapping[str, object]
    candidate_workload_ids: tuple[str, ...]
    outcome: str
    evaluated_at: datetime
    group_id: Optional[str] = None
    workload_id: Optional[str] = None
    incarnation_id: Optional[str] = None
    exposure_id: Optional[str] = None
    occurrence_id: Optional[str] = None
    candidate_explanations: tuple[Mapping[str, object], ...] = ()
    reason: Optional[str] = None
    supersedes_resolution_id: Optional[str] = None
    selected_exposure_revision: Optional[int] = None
    selected_occurrence_revision: Optional[int] = None
    known_group_revision: Optional[int] = None

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != SCHEMA_VERSION_V2:
            raise ValueError(f"unsupported schema_version {self.schema_version!r}")
        # Every UVM identity record ID is an immutable UUID (approved G1
        # Version 1 shared contracts); validate on construction.
        _require_v2_uuid(self.resolution_id, "resolution_id")
        _require_v2_uuid(self.observation_id, "observation_id")
        if type(self.candidate_workload_ids) not in (tuple, list):
            raise ValueError("candidate_workload_ids must be an array")
        for value in self.candidate_workload_ids:
            _require_v2_uuid(value, "candidate_workload_ids")
        for name in ("group_id", "workload_id", "incarnation_id",
                     "exposure_id", "occurrence_id", "supersedes_resolution_id"):
            value = getattr(self, name)
            if value is not None:
                _require_v2_uuid(value, name)
        if type(self.rule_id) is not str or not self.rule_id:
            raise ValueError("rule_id must be a nonempty string")
        if self.reason is not None and type(self.reason) is not str:
            raise ValueError("reason must be a string or null")
        if type(self.evaluated_at) is not datetime or self.evaluated_at.utcoffset() is None:
            raise ValueError("evaluated_at must be a timezone-aware datetime")
        if type(self.outcome) is not str or self.outcome not in OUTCOMES:
            raise ValueError(f"unsupported outcome {self.outcome!r}")
        # Record-level revision and rule_version are positive integer anchors.
        _require_positive_revision(self.revision, "revision")
        _require_positive_revision(self.rule_version, "rule_version")
        if self.outcome in (OUTCOME_MATCHED, OUTCOME_NEW):
            # All five selected IDs are mandatory for matched/new; a missing
            # selected ID cannot carry an anchor.
            for name in ("group_id", "workload_id", "incarnation_id",
                         "exposure_id", "occurrence_id"):
                if getattr(self, name) is None:
                    raise ValueError(
                        f"{self.outcome} resolution requires a selected {name}")
            _require_positive_revision(self.selected_exposure_revision,
                                       "selected_exposure_revision")
            _require_positive_revision(self.selected_occurrence_revision,
                                       "selected_occurrence_revision")
            if self.known_group_revision is not None:
                raise ValueError("selected resolution has no known-group-only anchor")
        else:
            # A known native group may survive ambiguous workload matching.
            # Neither ambiguous nor unresolved selects workload membership;
            # unresolved has no known group either. This mirrors the V1
            # persisted outcome constraint.
            selected_fields = ("workload_id", "incarnation_id", "exposure_id",
                               "occurrence_id")
            if self.outcome == OUTCOME_UNRESOLVED:
                if self.group_id is None and self.known_group_revision is not None:
                    raise ValueError("known_group_revision requires a known group")
                if self.group_id is not None:
                    _require_positive_revision(self.known_group_revision,
                                               "known_group_revision")
            elif self.known_group_revision is not None:
                raise ValueError("known_group_revision is only valid for grouped unresolved V2")
            for name in selected_fields:
                if getattr(self, name) is not None:
                    raise ValueError(
                        f"{self.outcome} resolution selects no {name}")
            if (self.selected_exposure_revision is not None
                    or self.selected_occurrence_revision is not None):
                raise ValueError(
                    f"{self.outcome} resolution selects no membership or anchor")
        if self.outcome == OUTCOME_AMBIGUOUS:
            candidate_ids = self.candidate_workload_ids
            if len(candidate_ids) < 2 or len(set(candidate_ids)) != len(candidate_ids):
                raise ValueError("ambiguous resolution requires distinct workload candidates")
        if type(self.matching_inputs) not in (dict, types.MappingProxyType):
            raise ValueError("matching_inputs must be an object")
        if type(self.candidate_explanations) not in (tuple, list):
            raise ValueError("candidate_explanations must be an array")
        for explanation in self.candidate_explanations:
            if type(explanation) not in (dict, types.MappingProxyType):
                raise ValueError("candidate_explanations must contain objects")
        if self.outcome == OUTCOME_AMBIGUOUS:
            explanation_ids = []
            for explanation in self.candidate_explanations:
                candidate_id = explanation.get("workload_id")
                _require_v2_uuid(candidate_id, "candidate_explanations.workload_id")
                explanation_ids.append(candidate_id)
            if (len(explanation_ids) != len(self.candidate_workload_ids)
                    or len(set(explanation_ids)) != len(explanation_ids)
                    or set(explanation_ids) != set(self.candidate_workload_ids)):
                raise ValueError(
                    "ambiguous resolution requires one explanation per workload candidate")
        object.__setattr__(self, "evaluated_at",
                           self.evaluated_at.astimezone(timezone.utc))
        object.__setattr__(self, "candidate_workload_ids",
                           tuple(self.candidate_workload_ids))
        object.__setattr__(self, "matching_inputs",
                           _copy_json_evidence(self.matching_inputs,
                                               "matching_inputs", immutable=True))
        object.__setattr__(self, "candidate_explanations",
                           tuple(_copy_json_evidence(explanation,
                                                     f"candidate_explanations[{index}]",
                                                     immutable=True)
                                 for index, explanation in enumerate(
                                     self.candidate_explanations)))
        # The DTO promises JSON-ready primitives. Check with the same standard
        # encoder callers use so oversized integers and excessive nesting do
        # not escape construction only to fail at the persistence boundary.
        try:
            json.dumps(self.to_primitives(), allow_nan=False)
        except (ValueError, TypeError, OverflowError, RecursionError) as exc:
            raise ValueError(
                "IdentityResolutionV2 evidence must be JSON-serialisable"
            ) from exc

    def to_primitives(self) -> dict[str, object]:
        """Return a fresh JSON-ready representation; never exposes DTO storage."""
        value = {item.name: getattr(self, item.name) for item in fields(self)}
        value["evaluated_at"] = self.evaluated_at.isoformat()
        return cast(dict[str, object], _copy_json_evidence(
            value, "IdentityResolutionV2", immutable=False))


@dataclass(frozen=True)
class CorrectionRecord:
    """Append-only identity correction/migration record (FR-ID-02): actor,
    reason, old/new mapping, evidence reference, affected records,
    correlation ID. Former IDs remain historical aliases."""

    correction_id: str
    record_type: str
    record_id: str
    old_value: Optional[str]
    new_value: Optional[str]
    actor: str
    reason: str
    correlation_id: str
    affected_record_ids: tuple[str, ...]
    created_at: datetime
    field_name: str = ""
    previous_revision: int = 0
    new_revision: int = 0
    assessment_impact: str = "unverified"
    issue_impact: str = "unverified"

    def __post_init__(self) -> None:
        # Every UVM identity record ID is an immutable UUID (approved G1
        # Version 1 shared contracts); validate on construction.
        _require_uuid(self.correction_id, "correction_id")
        _require_uuid(self.record_id, "record_id")
        for value in self.affected_record_ids:
            _require_uuid(value, "affected_record_ids")


class IdentityState:
    """In-memory identity state. All creation flows through this class so
    IDs are assigned exactly once and indexes stay consistent."""

    def __init__(self) -> None:
        self.groups: dict[str, Group] = {}
        self.groups_by_key: dict[NativeGroupKey, str] = {}
        self.cve_index: dict[str, set[str]] = {}
        self.workloads: dict[str, Workload] = {}
        self.incarnations: dict[str, Incarnation] = {}
        self.exposures: dict[str, Exposure] = {}
        self.occurrences: dict[str, Occurrence] = {}
        self._exposure_index: dict[tuple, str] = {}
        self._incarnation_index: dict[tuple, str] = {}
        self._occurrence_index: dict[tuple, str] = {}
        self.resolutions: list[IdentityResolutionV1] = []
        self.rule_definitions: dict[tuple[str, int], tuple[tuple[str, ...], bool, tuple[str, ...]]] = {}
        self.corrections: list[CorrectionRecord] = []
        self.aliases: dict[str, str] = {}  # former id/value -> current id
        self.mapping_aliases: dict[tuple, str] = {}
        # A native ID value is meaningful only within its complete namespace.
        self.group_key_aliases: dict[NativeGroupKey, str] = {}
        self.observation_occurrences: dict[str, str] = {}

    # -- group creation (CR-02) -------------------------------------------

    def find_or_create_group(self, key: NativeGroupKey, at: datetime) -> tuple[Group, bool]:
        existing = self.groups_by_key.get(key)
        if existing is not None:
            return self.groups[existing], False
        group = Group(group_id=new_id(), key=key, created_at=at)
        self.groups[group.group_id] = group
        self.groups_by_key[key] = group.group_id
        return group, True

    def add_cve_refs(self, group: Group, refs: tuple[str, ...] | list[str]) -> None:
        """Many-to-many CVE links. Shared CVE membership never merges groups."""
        for ref in refs:
            self.cve_index.setdefault(ref, set()).add(group.group_id)
            group.cve_refs.add(ref)

    def groups_for_cve(self, cve: str) -> set[str]:
        return set(self.cve_index.get(cve, ()))

    # -- workload / incarnation / exposure / occurrence --------------------

    def find_or_create_workload(
        self, stable_attrs: dict[str, str], at: datetime
    ) -> tuple[Workload, bool]:
        for w in self.workloads.values():
            if w.stable_attrs == stable_attrs:
                return w, False
        w = Workload(workload_id=new_id(), stable_attrs=dict(stable_attrs), created_at=at)
        self.workloads[w.workload_id] = w
        return w, True

    def find_or_create_incarnation(
        self, workload: Workload, host_locator: Optional[str], image_ref: Optional[str],
        first_observed_at: Optional[datetime], at: datetime, *,
        verified_reuse: bool = False,
    ) -> tuple[Incarnation, bool]:
        if not host_locator:
            raise ValueError("missing locator cannot identify an incarnation")
        key = (workload.workload_id, host_locator)
        existing = self._incarnation_index.get(key)
        if existing is not None:
            if not verified_reuse:
                raise ValueError("reused locator requires verified uniqueness")
            return self.incarnations[existing], False
        inc = Incarnation(
            incarnation_id=new_id(),
            workload_id=workload.workload_id,
            host_locator=host_locator,
            image_ref=image_ref,
            first_observed_at=first_observed_at,
            created_at=at,
        )
        self.incarnations[inc.incarnation_id] = inc
        self._incarnation_index[key] = inc.incarnation_id
        return inc, True

    def find_or_create_exposure(
        self, group: Group, workload: Workload, first_observed_at: Optional[datetime], at: datetime
    ) -> tuple[Exposure, bool]:
        key = (group.group_id, workload.workload_id)
        existing = self._exposure_index.get(key)
        if existing is not None:
            return self.exposures[existing], False
        exp = Exposure(
            exposure_id=new_id(),
            group_id=group.group_id,
            workload_id=workload.workload_id,
            first_observed_at=first_observed_at,
            created_at=at,
        )
        self.exposures[exp.exposure_id] = exp
        self._exposure_index[key] = exp.exposure_id
        return exp, True

    def find_or_create_occurrence(
        self,
        exposure: Exposure,
        incarnation: Incarnation,
        component_locator: Optional[str],
        first_observed_at: Optional[datetime],
        first_ingested_at: datetime,
    ) -> tuple[Occurrence, bool]:
        # Unknown component identity cannot prove that two calls refer to the
        # same remediable instance. Retained records may have their locator
        # withdrawn later through a correction, but direct creation requires
        # a known key (CR-04/FR-ID-02).
        if component_locator is None:
            raise ValueError("missing component locator cannot identify an occurrence")
        key = (exposure.exposure_id, incarnation.incarnation_id, component_locator)
        existing = self._occurrence_index.get(key)
        if existing is not None:
            return self.occurrences[existing], False
        occ = Occurrence(
            occurrence_id=new_id(),
            exposure_id=exposure.exposure_id,
            incarnation_id=incarnation.incarnation_id,
            component_locator=component_locator,
            first_observed_at=first_observed_at,
            first_ingested_at=first_ingested_at,
            created_at=first_ingested_at,
        )
        self.occurrences[occ.occurrence_id] = occ
        self._occurrence_index[key] = occ.occurrence_id
        return occ, True

    # -- provenance ---------------------------------------------------------

    def link_observation(self, observation_id: str, occurrence_id: str) -> None:
        """After safe resolution one observation refers to exactly one
        occurrence; a prior safe link is never silently replaced."""
        if observation_id in self.observation_occurrences:
            if self.observation_occurrences[observation_id] != occurrence_id:
                raise ValueError("observation already linked to a different occurrence")
            return
        self.observation_occurrences[observation_id] = occurrence_id

    def occurrence_for_observation(self, observation_id: str) -> Optional[str]:
        return self.observation_occurrences.get(observation_id)

    def resolution_for_observation(
        self, observation_id: str
    ) -> Optional[IdentityResolutionV1]:
        for res in reversed(self.resolutions):
            if res.observation_id == observation_id:
                return res
        return None

    # -- corrections (FR-ID-02) --------------------------------------------

    def record_correction(
        self,
        record_type: str,
        record_id: str,
        old_value: Optional[str],
        new_value: Optional[str],
        actor: str,
        reason: str,
        correlation_id: str,
        affected_record_ids: tuple[str, ...],
        at: datetime,
        *,
        field_name: Optional[str] = None,
    ) -> CorrectionRecord:
        """Apply a checked mapping correction, then append its impact history.

        This in-memory slice cannot assess downstream assessment or issue
        stores, so their impact remains explicitly unverified. Detection
        timestamps and historical resolution records are never rewritten.
        """
        bucket = {
            "workload": self.workloads,
            "incarnation": self.incarnations,
            "exposure": self.exposures,
            "occurrence": self.occurrences,
            "group": self.groups,
        }.get(record_type)
        if bucket is None or record_id not in bucket:
            raise ValueError("unknown correction target")
        if not actor or not reason or not correlation_id:
            raise ValueError("actor, reason and correlation ID are required")
        if at.tzinfo is None:
            raise ValueError("correction time must be timezone-aware")
        # Validate the full proposed correction record before any mutation so
        # a rejected correction never leaves changed state, indexes or
        # revisions behind (FR-ID-02 append-only lineage).
        for value in affected_record_ids:
            _require_uuid(value, "affected_record_ids")
        target = bucket[record_id]
        old_key = new_key = None
        if record_type == "workload":
            choices = [name for name, value in target.stable_attrs.items() if value == old_value]
            if field_name is None:
                if len(choices) != 1:
                    raise ValueError("correction field is ambiguous or absent")
                field_name = choices[0]
            if field_name not in choices or new_value is None:
                raise ValueError("workload correction must replace an existing stable field")
            # A correction must not create an ambiguous duplicate stable key.
            if any(w.workload_id != record_id and w.stable_attrs.get(field_name) == new_value
                   for w in self.workloads.values()):
                raise ValueError("corrected stable value belongs to another workload")
        elif record_type == "group":
            choices = [name for name in NativeGroupKey.__dataclass_fields__
                       if getattr(target.key, name) == old_value]
            if field_name is None:
                if len(choices) != 1:
                    raise ValueError("correction field is ambiguous or absent")
                field_name = choices[0]
            if field_name not in choices or new_value is None:
                raise ValueError("invalid group correction")
            old_key = target.key
            new_key = NativeGroupKey(**{**vars(old_key), field_name: new_value})
            if new_key in self.groups_by_key and self.groups_by_key[new_key] != record_id:
                raise ValueError("corrected group key belongs to another group")
            # A key historical to another group is never reused; a key
            # historical to this same record may be corrected back (retired
            # below so it becomes active again).
            if self.group_key_aliases.get(new_key) not in (None, record_id):
                raise ValueError("corrected group key is a historical alias")
        else:
            fields = {"incarnation": ("host_locator",),
                      "exposure": ("group_id", "workload_id"),
                      "occurrence": ("exposure_id", "incarnation_id", "component_locator")}[record_type]
            choices = [name for name in fields if getattr(target, name) == old_value]
            if field_name is None:
                if len(choices) != 1:
                    raise ValueError("correction field is ambiguous or absent")
                field_name = choices[0]
            if field_name not in choices:
                raise ValueError("old mapping does not match the target")
            if field_name in ("group_id", "workload_id", "exposure_id", "incarnation_id"):
                refs = {"group_id": self.groups, "workload_id": self.workloads,
                        "exposure_id": self.exposures, "incarnation_id": self.incarnations}
                if new_value not in refs[field_name]:
                    raise ValueError("new mapping target does not exist")
            if record_type == "exposure" and field_name == "workload_id":
                if any(self.incarnations[o.incarnation_id].workload_id != new_value
                       for o in self.occurrences.values() if o.exposure_id == record_id):
                    raise ValueError("exposure workload correction would detach occurrence membership")
            if record_type == "occurrence":
                exposure_id = new_value if field_name == "exposure_id" else target.exposure_id
                incarnation_id = new_value if field_name == "incarnation_id" else target.incarnation_id
                if self.exposures[exposure_id].workload_id != self.incarnations[incarnation_id].workload_id:
                    raise ValueError("occurrence correction crosses workload membership")
            if record_type == "incarnation":
                index, old_key = self._incarnation_index, (target.workload_id, target.host_locator)
            elif record_type == "exposure":
                index, old_key = self._exposure_index, (target.group_id, target.workload_id)
            else:
                index, old_key = self._occurrence_index, (
                    target.exposure_id, target.incarnation_id, target.component_locator)
            values = {name: getattr(target, name) for name in fields}
            values[field_name] = new_value
            if record_type == "incarnation":
                new_key = (target.workload_id, values["host_locator"])
            elif record_type == "exposure":
                new_key = (values["group_id"], values["workload_id"])
            else:
                new_key = (values["exposure_id"], values["incarnation_id"],
                           values["component_locator"])
            # null is never an index or match key on ANY correction path:
            # if the corrected key would carry a null host/component
            # locator, regardless of which field is being corrected, no
            # (..., None) entry is written or collides (CR-03/04
            # locator-correction clarification).
            if record_type == "incarnation":
                nullable = values["host_locator"] is None
            elif record_type == "occurrence":
                nullable = values["component_locator"] is None
            else:
                nullable = False
            if not nullable:
                if new_key in index and index[new_key] != record_id:
                    raise ValueError("corrected mapping collides with another record")
        if old_value == new_value:
            raise ValueError("correction must change the mapping")
        # A corrected host locator is historical only for the workload that
        # owned the incarnation; the same locator under an unrelated workload
        # is not blocked, so the alias is keyed workload-scoped.
        alias_key = None
        if old_value is not None and record_type != "group":
            if record_type == "incarnation":
                alias_key = (record_type, field_name, target.workload_id, old_value)
            elif record_type == "exposure":
                # An exposure historical alias is scoped to the counterpart
                # that the correction does not touch: the workload for a
                # group mapping, the group for a workload mapping. Independent
                # exposures on different workloads may each retire the same
                # former value (CR-03/FR-ID-02).
                scope = target.group_id if field_name == "workload_id" else target.workload_id
                alias_key = (record_type, field_name, scope, old_value)
            else:
                # A withdrawn component locator is historical only within
                # its exposure and incarnation scope; the same locator name
                # under another incarnation is not blocked (CR-04/FR-ID-02).
                if record_type == "occurrence" and field_name == "component_locator":
                    alias_key = (record_type, field_name, target.exposure_id,
                                 target.incarnation_id, old_value)
                elif record_type == "occurrence" and field_name in (
                        "exposure_id", "incarnation_id"):
                    # Parent-mapping history is per-record: several
                    # occurrences legitimately share one former exposure or
                    # incarnation, so the alias cannot be claimed by one of
                    # them alone (FR-ID-02).
                    alias_key = (record_type, field_name, record_id, old_value)
                else:
                    alias_key = (record_type, field_name, old_value)
        if alias_key is not None and alias_key in self.mapping_aliases and self.mapping_aliases[alias_key] != record_id:
            raise ValueError("historical alias already belongs to another record")
        if record_type == "group" and old_key in self.group_key_aliases:
            raise ValueError("group key is already a historical alias")
        impacts = set(affected_record_ids)
        if record_type == "workload":
            impacts.update(e.exposure_id for e in self.exposures.values() if e.workload_id == record_id)
            impacts.update(i.incarnation_id for i in self.incarnations.values() if i.workload_id == record_id)
        if record_type == "group":
            impacts.update(e.exposure_id for e in self.exposures.values() if e.group_id == record_id)
        if record_type in ("incarnation", "exposure"):
            impacts.update(o.occurrence_id for o in self.occurrences.values()
                           if getattr(o, f"{record_type}_id") == record_id)
        if record_type == "occurrence":
            impacts.add(record_id)
        impacts.update(o.occurrence_id for o in self.occurrences.values()
                       if o.exposure_id in impacts or o.incarnation_id in impacts)
        impacts.update(observation_id for observation_id, occurrence_id
                       in self.observation_occurrences.items() if occurrence_id in impacts)
        # The row to append must validate before any mutation: a linked
        # observation id outside the UVM UUID contract cannot reject the
        # correction after the mapping, index or revision already changed
        # (FR-ID-02 append-only lineage).
        affected_ids = tuple(dict.fromkeys((*affected_record_ids, *sorted(impacts))))
        for value in affected_ids:
            _require_uuid(value, "affected_record_ids")
        # Versioned active/historical semantics: correcting a record back to
        # a value that is historical for that same record makes the value
        # active again, so its alias entry is retired. A value historical to
        # any other record is never reused. The retirement runs only after
        # every affected-ID/record validation above has passed and before
        # the final state commit, so a rejected correction never leaves the
        # alias retired (Reviewer 37abc457, FR-ID-02/CR-03).
        if new_value is not None and record_type != "group":
            if record_type == "incarnation":
                reversal_key = (record_type, field_name, target.workload_id, new_value)
            elif record_type == "exposure":
                scope = target.group_id if field_name == "workload_id" else target.workload_id
                reversal_key = (record_type, field_name, scope, new_value)
            elif record_type == "occurrence" and field_name == "component_locator":
                reversal_key = (record_type, field_name, target.exposure_id,
                                target.incarnation_id, new_value)
            elif record_type == "occurrence" and field_name in (
                    "exposure_id", "incarnation_id"):
                reversal_key = (record_type, field_name, record_id, new_value)
            else:
                reversal_key = (record_type, field_name, new_value)
            owner = self.mapping_aliases.get(reversal_key)
            if owner is not None:
                if owner != record_id:
                    raise ValueError("historical alias already belongs to another record")
                del self.mapping_aliases[reversal_key]
                if self.aliases.get(new_value) == record_id:
                    del self.aliases[new_value]
        elif (record_type == "group" and new_key is not None
                and self.group_key_aliases.get(new_key) == record_id):
            del self.group_key_aliases[new_key]
        previous_revision = target.revision
        # Every validation has completed. Mutate mapping and index together.
        if record_type == "workload":
            target.stable_attrs[field_name] = new_value
        elif record_type == "group":
            del self.groups_by_key[old_key]
            target.key = new_key
            self.groups_by_key[new_key] = record_id
        else:
            index.pop(old_key, None)
            setattr(target, field_name, new_value)
            if not nullable:
                index[new_key] = record_id
        target.revision += 1
        rec = CorrectionRecord(
            correction_id=new_id(),
            record_type=record_type,
            record_id=record_id,
            old_value=old_value,
            new_value=new_value,
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            affected_record_ids=affected_ids,
            created_at=at,
            field_name=field_name,
            previous_revision=previous_revision,
            new_revision=target.revision,
        )
        self.corrections.append(rec)
        if record_type == "group":
            self.group_key_aliases[old_key] = record_id
        elif old_value is not None:
            self.mapping_aliases[alias_key] = record_id
            self.aliases.setdefault(old_value, record_id)
        return rec

    def apply_membership_correction(
        self,
        exposure_id: str,
        new_workload_id: str,
        occurrence_memberships: dict[str, str],
        actor: str,
        reason: str,
        correlation_id: str,
        at: datetime,
    ) -> list[CorrectionRecord]:
        """Atomic multi-record correction moving a populated exposure to
        another workload (FR-ID-02 / CR-03, approved G1 design).

        ``occurrence_memberships`` must map every occurrence of the exposure
        to the reviewed successor incarnation that will hold it. Record IDs,
        first-observed/first-ingested times and observation links are
        preserved; the bundle appends one ``CorrectionRecord`` per changed
        record, all sharing ``correlation_id``. Every proposed membership and
        index collision is validated before any mutation, so a rejected
        bundle changes nothing. Downstream assessment/issue impact remains
        explicitly unverified.
        """
        exposure = self.exposures.get(exposure_id)
        if exposure is None:
            raise ValueError("unknown correction target")
        if new_workload_id not in self.workloads:
            raise ValueError("new mapping target does not exist")
        if new_workload_id == exposure.workload_id:
            raise ValueError("correction must change the mapping")
        if not actor or not reason or not correlation_id:
            raise ValueError("actor, reason and correlation ID are required")
        if at.tzinfo is None:
            raise ValueError("correction time must be timezone-aware")
        members = sorted((o for o in self.occurrences.values()
                          if o.exposure_id == exposure_id),
                         key=lambda o: o.occurrence_id)
        if not members:
            # Empty exposures use the scalar path, which retains the scoped
            # historical mapping (FR-ID-02).
            raise ValueError("populated exposure required; empty exposures use scalar correction")
        if set(occurrence_memberships) != {o.occurrence_id for o in members}:
            raise ValueError("membership bundle must cover every exposure occurrence exactly once")
        if self._exposure_index.get((exposure.group_id, new_workload_id)) \
                not in (None, exposure_id):
            raise ValueError("corrected mapping collides with another record")
        exp_alias_key = ("exposure", "workload_id", exposure.group_id,
                         exposure.workload_id)
        alias_owner = self.mapping_aliases.get(exp_alias_key)
        if alias_owner is not None and alias_owner != exposure_id:
            raise ValueError("historical alias already belongs to another record")
        # The proposed active mapping must not hold a value historical to
        # another exposure; only this exposure may reclaim its own retired
        # value (scalar-path resolver semantics, FR-ID-02/CR-03).
        reversal_key = ("exposure", "workload_id", exposure.group_id,
                        new_workload_id)
        reversal_owner = self.mapping_aliases.get(reversal_key)
        if reversal_owner is not None and reversal_owner != exposure_id:
            raise ValueError("historical alias already belongs to another record")
        proposed: list[tuple[Occurrence, str, str]] = []
        seen_keys: set[tuple] = set()
        for occ in members:
            new_incarnation_id = occurrence_memberships[occ.occurrence_id]
            incarnation = self.incarnations.get(new_incarnation_id)
            if incarnation is None:
                raise ValueError("new mapping target does not exist")
            if incarnation.workload_id != new_workload_id:
                raise ValueError("occurrence correction crosses workload membership")
            new_key = (exposure_id, new_incarnation_id, occ.component_locator)
            if occ.component_locator is not None and (
                    new_key in seen_keys or (
                        new_key in self._occurrence_index
                        and self._occurrence_index[new_key] != occ.occurrence_id)):
                # null is never an index or match key: distinct null-locator
                # occurrences may share one target scope without coalescing
                # (CR-03/04 locator-correction clarification).
                raise ValueError("corrected mapping collides with another record")
            seen_keys.add(new_key)
            occ_alias_key = ("occurrence", "incarnation_id", occ.occurrence_id,
                             occ.incarnation_id)
            owner = self.mapping_aliases.get(occ_alias_key)
            if owner is not None and owner != occ.occurrence_id:
                raise ValueError("historical alias already belongs to another record")
            proposed.append((occ, occ.incarnation_id, new_incarnation_id))
        # Every row to append must validate before any mutation: linked
        # observation ids outside the UVM UUID contract cannot reject the
        # bundle after a partial mutation (FR-ID-02 append-only lineage).
        impacted = {o.occurrence_id for o in members}
        impacted.update(obs for obs, occ_id in self.observation_occurrences.items()
                        if occ_id in impacted)
        for value in impacted:
            _require_uuid(value, "affected_record_ids")
        # Every validation has completed. Mutate mappings and indexes together.
        old_workload_id = exposure.workload_id
        # Observation links key off occurrence IDs, which are preserved; the
        # linked observations are impact of the records that own them.
        def _impact(record_ids: set[str]) -> tuple[str, ...]:
            ids = set(record_ids)
            ids.update(obs for obs, occ_id in self.observation_occurrences.items()
                       if occ_id in ids)
            return tuple(sorted(ids))
        exp_previous = exposure.revision
        self._exposure_index.pop((exposure.group_id, old_workload_id), None)
        self._exposure_index[(exposure.group_id, new_workload_id)] = exposure_id
        exposure.workload_id = new_workload_id
        exposure.revision = exp_previous + 1
        records = [CorrectionRecord(
            correction_id=new_id(), record_type="exposure",
            record_id=exposure_id, old_value=old_workload_id,
            new_value=new_workload_id, actor=actor, reason=reason,
            correlation_id=correlation_id,
            affected_record_ids=_impact({o.occurrence_id for o in members}),
            created_at=at, field_name="workload_id",
            previous_revision=exp_previous, new_revision=exposure.revision,
        )]
        for occ, old_incarnation_id, new_incarnation_id in proposed:
            previous = occ.revision
            if occ.component_locator is not None:
                # A null locator is never written to the occurrence index
                # (CR-03/04 locator-correction clarification).
                self._occurrence_index.pop(
                    (exposure_id, old_incarnation_id, occ.component_locator), None)
                self._occurrence_index[(exposure_id, new_incarnation_id,
                                        occ.component_locator)] = occ.occurrence_id
            occ.incarnation_id = new_incarnation_id
            occ.revision = previous + 1
            records.append(CorrectionRecord(
                correction_id=new_id(), record_type="occurrence",
                record_id=occ.occurrence_id, old_value=old_incarnation_id,
                new_value=new_incarnation_id, actor=actor, reason=reason,
                correlation_id=correlation_id,
                affected_record_ids=_impact({occ.occurrence_id}),
                created_at=at, field_name="incarnation_id",
                previous_revision=previous, new_revision=occ.revision,
            ))
        self.corrections.extend(records)
        self.mapping_aliases[exp_alias_key] = exposure_id
        self.aliases.setdefault(old_workload_id, exposure_id)
        if self.mapping_aliases.get(reversal_key) == exposure_id:
            del self.mapping_aliases[reversal_key]
        if self.aliases.get(new_workload_id) == exposure_id:
            del self.aliases[new_workload_id]
        for occ, old_incarnation_id, new_incarnation_id in proposed:
            self.mapping_aliases[("occurrence", "incarnation_id",
                                  occ.occurrence_id, old_incarnation_id)] \
                = occ.occurrence_id
            self.aliases.setdefault(old_incarnation_id, occ.occurrence_id)
            occ_reversal_key = ("occurrence", "incarnation_id",
                                occ.occurrence_id, new_incarnation_id)
            if self.mapping_aliases.get(occ_reversal_key) == occ.occurrence_id:
                del self.mapping_aliases[occ_reversal_key]
            if self.aliases.get(new_incarnation_id) == occ.occurrence_id:
                del self.aliases[new_incarnation_id]
        return records

    def resolve_group_alias(self, key: NativeGroupKey) -> Optional[str]:
        """Resolve a former native group key only within its full namespace."""
        return self.group_key_aliases.get(key)

    def resolve_alias(self, identifier: str, *, record_type: Optional[str] = None,
                      field_name: Optional[str] = None,
                      workload_id: Optional[str] = None,
                      scope: Optional[str] = None) -> str:
        if (record_type is None) != (field_name is None):
            raise ValueError("alias lookup requires both record type and field")
        if record_type is not None:
            if record_type == "incarnation" and workload_id is not None:
                # Host-locator aliases are workload-scoped.
                return self.mapping_aliases.get(
                    ("incarnation", field_name, workload_id, identifier), identifier)
            if record_type == "exposure":
                if scope is None:
                    raise ValueError(
                        "exposure alias lookup requires its counterpart scope")
                return self.mapping_aliases.get(
                    ("exposure", field_name, scope, identifier), identifier)
            return self.mapping_aliases.get((record_type, field_name, identifier), identifier)
        if any(identifier in bucket for bucket in
               (self.groups, self.workloads, self.incarnations, self.exposures, self.occurrences)):
            return identifier
        matches = {target for key, target in self.mapping_aliases.items()
                   if key[-1] == identifier}
        if len(matches) > 1:
            raise ValueError("historical alias is ambiguous without a record type and field")
        return next(iter(matches), identifier)
