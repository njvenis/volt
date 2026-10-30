"""Evidence-based identity resolver (G1 slice, FR-ID-01/02, CR-02/03/04).

The resolver matches a retained observation to a workload only through the
stable attributes named by the versioned rule. Ephemeral attributes (IP,
hostname, instance ID, image digest, component version) are recorded as
rejected evidence, never as a match. Outcomes are matched / new / ambiguous /
unresolved; ambiguity is queued with candidate explanations and no arbitrary
merge is performed. On verified workload correspondence a rebuild creates a
new incarnation and new occurrences while the exposure ID and earliest
supported detection are retained.
"""

from __future__ import annotations

from dataclasses import replace
from copy import deepcopy
from datetime import datetime
from typing import Optional

from uvm.identity.model import (
    OUTCOME_AMBIGUOUS,
    OUTCOME_MATCHED,
    OUTCOME_NEW,
    OUTCOME_UNRESOLVED,
    Group,
    IdentityResolutionV1,
    IdentityState,
    NativeGroupKey,
    Workload,
    new_id,
)
from uvm.identity.observations import MISSING_UNVERIFIED, SCHEMA_VERSION, SourceObservationV1


class RuleV1:
    """Versioned identity rule. Only ``workload_match_fields`` may prove
    workload correspondence (authoritative persistent provisioning/service
    keys per D-01 pending external-system proof); any other supplied input is
    treated as ephemeral and rejected."""

    def __init__(self, rule_id: str, rule_version: int, workload_match_fields: tuple[str, ...],
                 *, verified_asset_locator: bool = False,
                 workload_context_fields: tuple[str, ...] = ()) -> None:
        if not rule_id:
            raise ValueError("rule_id is required")
        if rule_version < 1:
            raise ValueError("rule_version must be a positive integer")
        if not workload_match_fields:
            raise ValueError("workload_match_fields must name at least one stable field")
        if any(not isinstance(field, str) or not field.strip() for field in workload_match_fields):
            raise ValueError("workload_match_fields must be non-empty names")
        if len(set(workload_match_fields)) != len(workload_match_fields):
            raise ValueError("workload_match_fields cannot repeat a field")
        ephemeral = {"ip", "ip_address", "hostname", "host_name", "instance_id",
                     "asset_locator", "image_digest", "image_ref", "component_version"}
        if any(field in ephemeral for field in workload_match_fields):
            raise ValueError("ephemeral attributes cannot prove workload correspondence")
        if type(workload_context_fields) is not tuple:
            raise ValueError("workload_context_fields must be an actual tuple")
        if any(type(field) is not str or not field or field != field.strip()
               for field in workload_context_fields):
            raise ValueError("workload_context_fields must contain non-empty trimmed strings")
        if len(set(workload_context_fields)) != len(workload_context_fields):
            raise ValueError("workload_context_fields cannot repeat a field")
        if set(workload_context_fields) & set(workload_match_fields):
            raise ValueError("workload context fields must be disjoint from match fields")
        if any(field in ephemeral for field in workload_context_fields):
            raise ValueError("ephemeral attributes cannot be retained as workload context")
        self.rule_id = rule_id
        self.rule_version = rule_version
        self.workload_match_fields: tuple[str, ...] = tuple(workload_match_fields)
        # Only set after source-specific uniqueness and reuse evidence is
        # established. D-01 is still open for live scanner fields.
        self.verified_asset_locator = verified_asset_locator
        self.workload_context_fields = workload_context_fields

    def matches(self, other: "RuleV1") -> bool:
        return (
            self.rule_id == other.rule_id
            and self.rule_version == other.rule_version
            and self.workload_match_fields == other.workload_match_fields
            and self.verified_asset_locator == other.verified_asset_locator
            and self.workload_context_fields == other.workload_context_fields
        )


def resolve(
    state: IdentityState,
    obs: SourceObservationV1,
    rule: RuleV1,
    matching_inputs: dict[str, str],
    evaluated_at: datetime,
) -> IdentityResolutionV1:
    """Resolve one retained observation under one rule version.

    ``matching_inputs`` are the workload attributes extracted by the caller
    (adapter) from the observation's locators; provenance is the
    observation plus the rule version recorded on the result.
    Appends the resolution record and returns it.
    """
    if evaluated_at.tzinfo is None:
        raise ValueError("evaluated_at must be a timezone-aware UTC instant")
    if any(not isinstance(value, str) for value in matching_inputs.values()):
        raise ValueError("matching inputs must be strings")
    rule_key = (rule.rule_id, rule.rule_version)
    rule_definition = (rule.workload_match_fields, rule.verified_asset_locator,
                       rule.workload_context_fields)
    if (rule_key in state.rule_definitions
            and state.rule_definitions[rule_key] != rule_definition):
        raise ValueError("rule definition changed without a new version")

    prior = state.resolution_for_observation(obs.observation_id)
    linked = state.occurrence_for_observation(obs.observation_id)
    if linked is not None:
        # Source observations are immutable. A changed resolution needs an
        # explicit correction, not a second automatic link. Do this before
        # creating any group, workload or incarnation records.
        occurrence = state.occurrences.get(linked)
        exposure = state.exposures.get(occurrence.exposure_id) if occurrence else None
        incarnation = state.incarnations.get(occurrence.incarnation_id) if occurrence else None
        if (prior is None or prior.occurrence_id != linked
                or prior.matching_inputs != matching_inputs
                or prior.rule_id != rule.rule_id or prior.rule_version != rule.rule_version
                or occurrence is None or exposure is None or incarnation is None
                or occurrence.component_locator != obs.component_locator
                or exposure.exposure_id != prior.exposure_id
                or exposure.group_id != prior.group_id
                or exposure.workload_id != prior.workload_id
                or incarnation.incarnation_id != prior.incarnation_id
                or incarnation.workload_id != prior.workload_id
                or incarnation.host_locator != obs.asset_locator
                or prior.group_id not in state.groups
                or state.groups[prior.group_id].key != NativeGroupKey(
                    obs.source_family, obs.native_id_scheme, obs.native_id_authority,
                    obs.native_id_value)):
            raise ValueError("linked observation requires an explicit correction to re-resolve")
        # The versioned contract (FR-ID-01) and the lineage schema keep the
        # prior row: a re-resolution of the same observation appends the next
        # revision, never rewrites or reuses revision 1 (UNIQUE on
        # (observation_id, revision)).
        repeated = replace(prior, resolution_id=new_id(), revision=prior.revision + 1,
                           evaluated_at=evaluated_at,
                           supersedes_resolution_id=prior.resolution_id)
        state.resolutions.append(repeated)
        return repeated

    explanations: list[dict] = []
    group: Optional[Group] = None
    group_is_new = False
    workload: Optional[Workload] = None
    workload_is_new = False

    # 1. Native group (CR-02): resolved independently of CVE links and of
    #    workload matching. A missing native identifier is a missing key:
    #    the observation stays unresolved, no group is invented.
    if not (obs.native_id_scheme and obs.native_id_authority and obs.native_id_value):
        return _record(
            state, obs, rule, matching_inputs, evaluated_at,
            outcome=OUTCOME_UNRESOLVED,
            candidates=(),
            explanations=(
                {"reason": "missing native identifier; no group or workload assigned",
                 "field": "native_id", "value": None},
            ),
            reason="missing native identifier key",
        )

    group_key = NativeGroupKey(
        source_family=obs.source_family,
        native_id_scheme=obs.native_id_scheme,
        native_id_authority=obs.native_id_authority,
        native_id_value=obs.native_id_value,
    )
    if state.resolve_group_alias(group_key) is not None:
        return _record(
            state, obs, rule, matching_inputs, evaluated_at,
            outcome=OUTCOME_UNRESOLVED, candidates=(),
            explanations=({"field": "native_group_key", "value": vars(group_key),
                           "reason": "historical native-group alias requires reviewed correspondence"},),
            reason="historical native group key; no new group guessed",
        )
    state_before_graph = deepcopy(state)
    group, group_is_new = state.find_or_create_group(group_key, at=evaluated_at)
    if obs.vulnerability_refs:
        state.add_cve_refs(group, obs.vulnerability_refs)

    if not obs.asset_locator:
        return _record(
            state, obs, rule, matching_inputs, evaluated_at,
            outcome=OUTCOME_UNRESOLVED, candidates=(), group=group,
            explanations=({"field": "asset_locator", "value": obs.asset_locator,
                           "reason": "missing asset locator cannot identify an incarnation"},),
            reason="missing asset locator; incarnation unresolved",
        )
    # Without a verified component locator, two source rows on the same host
    # cannot be proved to describe one remediable portion. Source-row locators
    # are retained evidence, but their uniqueness across reports is unproved.
    if (not obs.component_locator or not obs.component_locator.strip()
            or any(m.field == "component_locator" and m.reason == MISSING_UNVERIFIED
                   for m in obs.missing_fields)):
        return _record(
            state, obs, rule, matching_inputs, evaluated_at,
            outcome=OUTCOME_UNRESOLVED, candidates=(), group=group,
            explanations=({"field": "component_locator", "value": obs.component_locator,
                           "source_record_locator": obs.source_record_locator,
                           "reason": "component identity unverified; source row does not prove occurrence membership"},),
            reason="component locator unverified; occurrence unresolved",
        )

    historical_workload_fields = [(field, matching_inputs[field])
                                  for field in rule.workload_match_fields
                                  if field in matching_inputs and
                                  ("workload", field, matching_inputs[field]) in state.mapping_aliases]
    if historical_workload_fields:
        return _record(
            state, obs, rule, matching_inputs, evaluated_at,
            outcome=OUTCOME_UNRESOLVED, candidates=(), group=group,
            explanations=tuple(
                {"field": field, "value": value,
                 "reason": "historical stable alias requires reviewed correspondence"}
                for field, value in historical_workload_fields),
            reason="historical stable value; no workload guessed",
        )

    # 2. Workload correspondence via stable rule fields only.
    evidence: dict[str, list[tuple[str, str]]] = {}
    contradicted: dict[str, list[tuple[str, str, str]]] = {}
    for field in rule.workload_match_fields:
        value = matching_inputs.get(field)
        if not value or not value.strip():
            continue
        for w in state.workloads.values():
            if w.stable_attrs.get(field) == value:
                evidence.setdefault(w.workload_id, []).append((field, value))
    for wid in evidence:
        w = state.workloads[wid]
        for field in rule.workload_match_fields:
            supplied = matching_inputs.get(field)
            current = w.stable_attrs.get(field)
            if supplied and supplied.strip() and current is not None and supplied != current:
                contradicted.setdefault(wid, []).append((field, supplied, current))
    for wid, conflicts in contradicted.items():
        for field, supplied, current in conflicts:
            explanations.append({"workload_id": wid, "field": field, "value": supplied,
                                 "stored_value": current,
                                 "reason": "configured stable field contradicts existing workload"})
    valid_evidence = {wid: matches for wid, matches in evidence.items()
                      if wid not in contradicted}
    for field, value in matching_inputs.items():
        if field in rule.workload_match_fields:
            continue
        for w in state.workloads.values():
            if w.stable_attrs.get(field) == value:
                explanations.append(
                    {
                        "workload_id": w.workload_id,
                        "field": field,
                        "value": value,
                        "reason": f"ephemeral field {field!r} cannot prove workload correspondence",
                    }
                )

    if contradicted:
        return _record(
            state, obs, rule, matching_inputs, evaluated_at,
            outcome=OUTCOME_UNRESOLVED,
            candidates=tuple(sorted(evidence)), explanations=tuple(explanations),
            group=group,
            reason="contradictory stable workload evidence; no match guessed",
        )

    if len(valid_evidence) > 1:
        candidates = tuple(sorted(valid_evidence))
        for wid in candidates:
            for field, value in valid_evidence[wid]:
                explanations.append(
                    {"workload_id": wid, "field": field, "value": value,
                     "reason": "stable attribute match; at least two plausible workloads"}
                )
        return _record(
            state, obs, rule, matching_inputs, evaluated_at,
            outcome=OUTCOME_AMBIGUOUS,
            candidates=candidates,
            explanations=tuple(explanations),
            group=group,
            reason="ambiguous workload correspondence; queued, no match guessed",
        )

    if valid_evidence:
        (workload_id, _), = valid_evidence.items()
        workload = state.workloads[workload_id]
        for field, value in valid_evidence[workload_id]:
            explanations.append(
                {"workload_id": workload_id, "field": field, "value": value,
                 "reason": "stable attribute match"}
            )
        context_conflicts = []
        for field in rule.workload_context_fields:
            value = matching_inputs.get(field)
            if value is None:
                continue
            if type(value) is not str or not value.strip():
                raise ValueError("workload context values must be non-empty strings")
            retained = workload.stable_attrs.get(field)
            if retained is not None and retained != value:
                context_conflicts.append((field, value, retained))
        if context_conflicts:
            state.__dict__.clear()
            state.__dict__.update(state_before_graph.__dict__)
            return _record(state, obs, rule, matching_inputs, evaluated_at,
                outcome=OUTCOME_UNRESOLVED, candidates=(workload_id,),
                explanations=tuple(explanations) + tuple(
                    {"workload_id": workload_id, "field": field, "value": supplied,
                     "stored_value": retained,
                     "reason": "supplied workload context conflicts with retained context"}
                    for field, supplied, retained in context_conflicts),
                reason="workload context conflict; no graph or SLA mutation")
        # A corrected host locator is historical only for the workload that
        # owned the incarnation; the same locator under an unrelated
        # workload is not blocked (the alias is keyed workload-scoped).
        # A new workload cannot own a corrected incarnation, so the check
        # applies to matched workloads only.
        if not workload_is_new and (
            "incarnation", "host_locator", workload.workload_id, obs.asset_locator
        ) in state.mapping_aliases:
            return _record(
                state, obs, rule, matching_inputs, evaluated_at,
                outcome=OUTCOME_UNRESOLVED, candidates=(workload.workload_id,),
                explanations=tuple(explanations) + (
                    {"field": "asset_locator", "value": obs.asset_locator,
                     "reason": "historical host-locator alias requires reviewed correspondence"},),
                group=group, reason="historical asset locator; incarnation unresolved",
            )
    else:
        supplied = {f: v for f, v in matching_inputs.items()
                    if f in rule.workload_match_fields and v.strip()}
        if not supplied:
            return _record(
                state, obs, rule, matching_inputs, evaluated_at,
                outcome=OUTCOME_UNRESOLVED,
                candidates=(),
                explanations=tuple(explanations),
                group=group,
                reason="no stable workload attributes supplied; no match guessed",
            )
        workload, workload_is_new = state.find_or_create_workload(supplied, at=evaluated_at)
        if workload_is_new:
            for field in rule.workload_context_fields:
                value = matching_inputs.get(field)
                if value is not None:
                    if type(value) is not str or not value.strip():
                        raise ValueError("workload context values must be non-empty strings")
                    workload.stable_attrs[field] = value

    existing_incarnation = state._incarnation_index.get((workload.workload_id, obs.asset_locator))
    if existing_incarnation is not None and not rule.verified_asset_locator:
        return _record(
            state, obs, rule, matching_inputs, evaluated_at,
            outcome=OUTCOME_UNRESOLVED, candidates=(workload.workload_id,),
            explanations=tuple(explanations) + (
                {"field": "asset_locator", "value": obs.asset_locator,
                 "reason": "reused locator has no verified uniqueness across incarnations"},),
            group=group, reason="reused asset locator; incarnation unresolved",
        )
    # A corrected exposure's former group/workload relation needs reviewed
    # correspondence whichever side of that relation changed. Both aliases
    # are scoped to the unchanged counterpart, so unrelated relations remain
    # available for automatic resolution (CR-03/FR-ID-02).
    if ("exposure", "group_id", workload.workload_id, group.group_id) in state.mapping_aliases:
        return _record(
            state, obs, rule, matching_inputs, evaluated_at,
            outcome=OUTCOME_UNRESOLVED, candidates=(workload.workload_id,),
            explanations=tuple(explanations) + (
                {"field": "native_group_id", "value": group.group_id,
                 "reason": "historical exposure group alias requires reviewed correspondence"},),
            group=group, workload=workload,
            reason="historical exposure group; replacement exposure not created",
        )
    if ("exposure", "workload_id", group.group_id, workload.workload_id) in state.mapping_aliases:
        return _record(
            state, obs, rule, matching_inputs, evaluated_at,
            outcome=OUTCOME_UNRESOLVED, candidates=(workload.workload_id,),
            explanations=tuple(explanations) + (
                {"field": "workload_id", "value": workload.workload_id,
                 "reason": "historical exposure workload alias requires reviewed correspondence"},),
            group=group, workload=workload,
            reason="historical exposure workload; replacement exposure not created",
        )
    # A withdrawn component locator is historical evidence: replaying the
    # same locator in the same exposure/incarnation scope stays unresolved
    # until a reviewed correction (CR-04/FR-ID-02). The scope is looked up
    # without creating records, so an unresolved replay creates nothing.
    existing_exposure = state._exposure_index.get((group.group_id, workload.workload_id))
    if (existing_exposure is not None and existing_incarnation is not None
            and ("occurrence", "component_locator", existing_exposure,
                 existing_incarnation, obs.component_locator)
            in state.mapping_aliases):
        return _record(
            state, obs, rule, matching_inputs, evaluated_at,
            outcome=OUTCOME_UNRESOLVED, candidates=(workload.workload_id,),
            explanations=tuple(explanations) + (
                {"field": "component_locator", "value": obs.component_locator,
                 "reason": "historical component locator requires reviewed correspondence"},),
            group=group, workload=workload,
            reason="historical component locator; occurrence unresolved",
        )

    # 3. Incarnation / exposure / occurrence. A replacement host (new asset
    #    locator under the same verified workload) creates a new incarnation
    #    and new occurrences; the exposure and its earliest supported
    #    detection are retained (CR-03). Same-role replicas are distinct
    #    incarnations of the same workload.
    incarnation, inc_is_new = state.find_or_create_incarnation(
        workload,
        host_locator=obs.asset_locator,
        image_ref=None,
        first_observed_at=obs.observed_at,
        at=evaluated_at,
        verified_reuse=rule.verified_asset_locator,
    )
    # First supported detection is fixed from the observation that creates
    # the exposure and retained on verified succession; an unknown stays
    # unknown until an audited correction (CR-03, FR-ID-02).
    exposure, _ = state.find_or_create_exposure(
        group, workload, first_observed_at=obs.observed_at, at=evaluated_at
    )
    occurrence, _ = state.find_or_create_occurrence(
        exposure,
        incarnation,
        component_locator=obs.component_locator,
        # First observation on this portion; unknown stays unknown, never the
        # collection time.
        first_observed_at=obs.observed_at,
        first_ingested_at=evaluated_at,
    )

    outcome = OUTCOME_NEW if (group_is_new or workload_is_new) else OUTCOME_MATCHED
    if inc_is_new and not (group_is_new or workload_is_new):
        explanations.append(
            {"workload_id": workload.workload_id, "field": "asset_locator",
             "value": obs.asset_locator,
             "reason": "new incarnation; exposure and earliest detection retained (verified rebuild)"}
        )
    state.link_observation(obs.observation_id, occurrence.occurrence_id)

    return _record(
        state, obs, rule, matching_inputs, evaluated_at,
        outcome=outcome,
        candidates=(workload.workload_id,),
        explanations=tuple(explanations),
        group=group,
        workload=workload,
        incarnation_id=incarnation.incarnation_id,
        exposure_id=exposure.exposure_id,
        occurrence_id=occurrence.occurrence_id,
        reason="matched existing identity" if outcome == OUTCOME_MATCHED else "new identity created",
    )


def _record(
    state: IdentityState,
    obs: SourceObservationV1,
    rule: RuleV1,
    matching_inputs: dict[str, str],
    evaluated_at: datetime,
    outcome: str,
    candidates: tuple[str, ...],
    explanations: tuple[dict, ...],
    group: Optional[Group] = None,
    workload: Optional[Workload] = None,
    incarnation_id: Optional[str] = None,
    exposure_id: Optional[str] = None,
    occurrence_id: Optional[str] = None,
    reason: Optional[str] = None,
) -> IdentityResolutionV1:
    state.rule_definitions[(rule.rule_id, rule.rule_version)] = (
        rule.workload_match_fields, rule.verified_asset_locator,
        rule.workload_context_fields)
    prior = state.resolution_for_observation(obs.observation_id)
    res = IdentityResolutionV1(
        schema_version=SCHEMA_VERSION,
        resolution_id=new_id(),
        # A retained earlier resolution for the same observation means this
        # is a re-resolution: append the next revision, retain the prior row
        # (UNIQUE on (observation_id, revision)).
        revision=prior.revision + 1 if prior is not None else 1,
        observation_id=obs.observation_id,
        rule_id=rule.rule_id,
        rule_version=rule.rule_version,
        matching_inputs=dict(matching_inputs),
        candidate_workload_ids=candidates,
        outcome=outcome,
        evaluated_at=evaluated_at,
        group_id=group.group_id if group else None,
        workload_id=workload.workload_id if workload else None,
        incarnation_id=incarnation_id,
        exposure_id=exposure_id,
        occurrence_id=occurrence_id,
        candidate_explanations=explanations,
        reason=reason,
        supersedes_resolution_id=prior.resolution_id if prior is not None else None,
    )
    state.resolutions.append(res)
    return res
