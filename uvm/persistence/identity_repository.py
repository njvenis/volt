"""Durable, connection-scoped identity resolution boundary (G2 2.5b).

This is the sole public owner of retained resolution transactions.  It restores
the complete deployment graph before invoking the existing resolver and uses
the existing occurrence/V2 guards on the same SQLAlchemy connection.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, DecimalException

import sqlalchemy as sa

from uvm.identity.model import (
    CorrectionRecord, Exposure, Group, IdentityResolutionV1, IdentityResolutionV2, IdentityState,
    Incarnation, NativeGroupKey, Occurrence, Workload,
)
from uvm.identity.resolver import RuleV1, resolve
from uvm.persistence.alias_schema import group_key_alias_events, mapping_alias_events
from uvm.persistence.identity_resolution_store import IdentityResolutionStore
from uvm.persistence.occurrence_store import OccurrenceCreate, OccurrenceStore
from uvm.persistence.lineage_schema import (
    correction_records, identity_resolution_requests, identity_resolutions,
    identity_rule_definitions, identity_authorisation_decisions,
)
from uvm.persistence.observation_schema import source_observations
from uvm.persistence.observation_store import _ingest_fields, _row_to_observation
from uvm.persistence.schema import (
    exposure_workload_memberships, exposures, group_cve_refs, groups,
    incarnations, occurrences, workloads,
)
from uvm.persistence.scalar_schema import identity_scalar_correction_receipts  # noqa: F401
from uvm.persistence.g4_schema import exposure_episodes, exposure_episode_members
from uvm.persistence.metrics_schema import sla_policy_versions
from uvm.persistence.exception_sla_schema import (sla_ingest_receipts,
    source_observation_receipts, sla_episode_contracts)
from uvm.persistence.identity_graph_lock import lock_identity_graph

UTC = timezone.utc


class DurableIdentityError(ValueError):
    pass


class ResolutionRequestConflict(DurableIdentityError):
    pass


@dataclass(frozen=True)
class AuthorisationDecision:
    """Result supplied by a trusted server evaluator, never by a request body."""
    decision_id: str
    allowed: bool
    principal_id: str
    action: str
    target_id: str
    scope: str
    policy_revision: str
    reason: str
    evidence_ref: str
    correlation_id: str
    decided_at: datetime
    details: dict


def _uuid(value, name):
    try:
        parsed = uuid.UUID(value)
    except (TypeError, ValueError, AttributeError):
        raise DurableIdentityError(f"{name} must be a canonical UUID") from None
    if str(parsed) != value:
        raise DurableIdentityError(f"{name} must be a canonical UUID")
    return value


def _utc(value):
    if value.tzinfo is None:
        raise DurableIdentityError("evaluated_at must be timezone-aware")
    return value.astimezone(UTC)


class IdentityRepository:
    """Restore and resolve retained observations atomically."""

    def __init__(self, engine, authorisation_evaluator=None):
        self.engine = engine
        self.authorisation_evaluator = authorisation_evaluator
        self._resolution_store = IdentityResolutionStore(engine)
        self._occurrence_store = OccurrenceStore(engine)

    def correct_scalar_field(self, request, *, principal_id):
        """Supported H4 supplier action; no assessment HTTP command."""
        from uvm.persistence.scalar_correction import correct_scalar_field
        return correct_scalar_field(self, request, principal_id=principal_id)

    def record_deadline_reference(self, reference, *, expected_occurrence_revision,
                                  expected_reference_revision, provenance_bytes):
        """Append supplied history through current trusted identity authority."""
        from uvm.persistence.deadline_reference_store import DeadlineReferenceStore
        return DeadlineReferenceStore(self.engine, self._authorise).write(reference,
            expected_occurrence_revision=expected_occurrence_revision,
            expected_reference_revision=expected_reference_revision,
            provenance_bytes=provenance_bytes)

    def read_deadline_reference_history(self, occurrence_id):
        from uvm.persistence.deadline_reference_store import DeadlineReferenceStore
        with self.engine.connect() as connection:
            return DeadlineReferenceStore.read_history_on_connection(connection, occurrence_id)

    @staticmethod
    def _rule_digest(rule):
        payload = {"fields": rule.workload_match_fields,
            "verified_asset_locator": rule.verified_asset_locator}
        if rule.workload_context_fields:
            payload["workload_context_fields"] = list(rule.workload_context_fields)
        definition = json.dumps(payload,
            sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(definition).hexdigest()

    @staticmethod
    def _stored_context_fields(value, match_fields):
        if type(value) is not list or any(type(field) is not str or not field
                or field != field.strip() for field in value):
            raise DurableIdentityError("stored workload context fields are not a valid JSON array")
        if len(set(value)) != len(value) or set(value) & set(match_fields):
            raise DurableIdentityError("stored workload context fields are duplicate or overlap match fields")
        return tuple(value)

    @staticmethod
    def _request_fingerprint(*, observation_id, observation_revision, rule,
            matching_inputs, evaluated_at):
        payload = {
            "observation_id": observation_id,
            "observation_revision": observation_revision,
            "rule_id": rule.rule_id,
            "rule_version": rule.rule_version,
            "rule_fields": rule.workload_match_fields,
            "verified_asset_locator": rule.verified_asset_locator,
            "matching_inputs": matching_inputs,
            "evaluated_at": evaluated_at.isoformat(),
        }
        if rule.workload_context_fields:
            payload["workload_context_fields"] = list(rule.workload_context_fields)
        return hashlib.sha256(json.dumps(payload, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode()).hexdigest()

    def provision_rule(self, rule, created_at):
        """Provision immutable configuration separately from resolution."""
        if not isinstance(rule, RuleV1):
            raise DurableIdentityError("rule must be RuleV1")
        at = _utc(created_at)
        digest = self._rule_digest(rule)
        with self.engine.begin() as conn:
            existing = conn.execute(sa.select(identity_rule_definitions).where(
                identity_rule_definitions.c.rule_id == rule.rule_id,
                identity_rule_definitions.c.rule_version == rule.rule_version)).mappings().first()
            if existing:
                if (existing["definition_digest"] != digest
                        or tuple(existing["workload_match_fields"]) != rule.workload_match_fields
                        or self._stored_context_fields(existing["workload_context_fields"],
                            existing["workload_match_fields"]) != rule.workload_context_fields
                        or existing["verified_asset_locator"] != rule.verified_asset_locator):
                    raise DurableIdentityError("immutable rule definition changed")
                return
            config_id = str(uuid.uuid5(uuid.NAMESPACE_URL,
                f"identity-rule:{rule.rule_id}:{rule.rule_version}:{digest}"))
            decision = self._authorise(conn, "identity.rule_provision", config_id,
                {"request_id": config_id, "rule_id": rule.rule_id,
                 "rule_version": rule.rule_version, "definition_digest": digest})
            conn.execute(identity_rule_definitions.insert().values(
                rule_id=rule.rule_id, rule_version=rule.rule_version,
                workload_match_fields=list(rule.workload_match_fields),
                workload_context_fields=list(rule.workload_context_fields),
                verified_asset_locator=rule.verified_asset_locator,
                definition_digest=digest, authorisation_decision_id=decision.decision_id,
                created_at=at))

    def _authorise(self, conn, action, target_id, context, *, persist=True, decision=None):
        if self.authorisation_evaluator is None:
            raise DurableIdentityError("trusted authorisation evaluator is required")
        if decision is None:
            decision = self.authorisation_evaluator(action, target_id, context)
        if (not isinstance(decision, AuthorisationDecision)
                or type(decision.allowed) is not bool or not decision.allowed):
            raise DurableIdentityError("trusted authorisation denied or returned no decision")
        _uuid(decision.decision_id, "decision_id")
        if (decision.action != action or decision.target_id != target_id
                or any(type(value) is not str or not value for value in (
                    decision.principal_id, decision.scope, decision.policy_revision,
                    decision.reason, decision.evidence_ref, decision.correlation_id))):
            raise DurableIdentityError("authorisation decision does not bind this action and target")
        at = _utc(decision.decided_at)
        details = json.loads(json.dumps(decision.details, allow_nan=False))
        if not isinstance(details, dict):
            raise DurableIdentityError("authorisation details must be an object")
        if persist:
            conn.execute(identity_authorisation_decisions.insert().values(
                decision_id=decision.decision_id, action=action, target_id=target_id,
                principal_id=decision.principal_id, scope=decision.scope,
                policy_revision=decision.policy_revision, reason=decision.reason,
                evidence_ref=decision.evidence_ref,
                correlation_id=decision.correlation_id, decided_at=at,
                decision_details=details,
                decision_semantics_canonical=self._decision_semantics(decision)))
        return decision

    @staticmethod
    def _decision_semantics(decision):
        """Canonical JSON of a live or retained authorisation's decision content.

        Decision ID, time, evidence and correlation references may be fresh
        on an exact resend; every other field binds the correction.  Compare
        the encoded text, not decoded objects: Python equates true, 1 and 1.0."""
        if isinstance(decision, sa.RowMapping):
            # Only allowed decisions are ever retained.
            allowed, details = True, decision["decision_details"]
            get = decision.__getitem__
        else:
            allowed, details = decision.allowed, decision.details
            get = lambda name: getattr(decision, name)
        semantics = {name: get(name) for name in (
            "principal_id", "action", "target_id", "scope", "policy_revision", "reason")}
        semantics["allowed"] = allowed
        semantics["details"] = details
        return json.dumps(semantics, sort_keys=True, separators=(",", ":"),
                          allow_nan=False)

    @classmethod
    def _retained_decision_matches(cls, retained, fresh):
        """Typed text is authoritative; JSONB is a checked readable projection.

        JSONB can expand exponent numbers and discard numeric spelling. Compare
        numbers as decimal values only in the projection, never for the fresh
        decision or request fingerprint. Bool is a distinct JSON type throughout.
        """
        if retained is None or retained["decision_semantics_canonical"] is None:
            return False
        canonical = retained["decision_semantics_canonical"]
        if canonical != cls._decision_semantics(fresh):
            return False

        def reject_constant(value):
            raise ValueError("non-standard JSON constant")

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON object key")
                result[key] = value
            return result

        def exact_json(value):
            return json.loads(value, parse_int=Decimal, parse_float=Decimal,
                              parse_constant=reject_constant,
                              object_pairs_hook=unique_object)

        try:
            expected = exact_json(canonical)
            # The SELECT casts JSON/JSONB to text before any driver or
            # SQLAlchemy JSON decoding can round a retained numeric token.
            details = exact_json(retained["decision_details"])
            if not isinstance(details, dict):
                return False
            projection = {name: retained[name] for name in (
                "principal_id", "action", "target_id", "scope", "policy_revision", "reason")}
            projection.update(allowed=True, details=details)
        except (ValueError, TypeError, RecursionError, DecimalException):
            return False

        def same(left, right):
            if type(left) is not type(right):
                return False
            if isinstance(left, dict):
                return left.keys() == right.keys() and all(
                    same(value, right[key]) for key, value in left.items())
            if isinstance(left, list):
                return len(left) == len(right) and all(
                    same(a, b) for a, b in zip(left, right))
            return left == right

        return same(expected, projection)

    def restore_state(self, conn=None) -> IdentityState:
        """Restore every identity candidate in this deployment.

        The optional connection is intentional: callers inside the public
        transaction never obtain a second connection.
        """
        owns = conn is None
        if owns:
            conn = self.engine.connect()
        try:
            state = IdentityState()
            now = datetime.now(UTC)
            def dt(value):
                return value if value is None or value.tzinfo else value.replace(tzinfo=UTC)
            for row in conn.execute(sa.select(groups)).mappings():
                key = NativeGroupKey(row["source_family"], row["native_id_scheme"],
                                     row["native_id_authority"], row["native_id_value"])
                item = Group(row["group_id"], key, revision=row["revision"], created_at=dt(row["created_at"]))
                item.cve_refs = set(conn.execute(sa.select(group_cve_refs.c.cve_ref).where(
                    group_cve_refs.c.group_id == item.group_id)).scalars())
                state.groups[item.group_id] = item
                state.groups_by_key[key] = item.group_id
                for cve in item.cve_refs:
                    state.cve_index.setdefault(cve, set()).add(item.group_id)
            for row in conn.execute(sa.select(workloads)).mappings():
                item = Workload(row["workload_id"], dict(row["stable_attrs"]), row["revision"], dt(row["created_at"]))
                state.workloads[item.workload_id] = item
            for row in conn.execute(sa.select(incarnations)).mappings():
                if row["workload_id"] not in state.workloads:
                    raise DurableIdentityError("incarnation references missing workload")
                item = Incarnation(row["incarnation_id"], row["workload_id"], row["host_locator"],
                                   row["image_ref"], dt(row["first_observed_at"]), row["revision"], dt(row["created_at"]))
                state.incarnations[item.incarnation_id] = item
                if item.host_locator:
                    state._incarnation_index[(item.workload_id, item.host_locator)] = item.incarnation_id
            for row in conn.execute(sa.select(exposures)).mappings():
                if row["group_id"] not in state.groups or row["workload_id"] not in state.workloads:
                    raise DurableIdentityError("exposure references missing group or workload")
                item = Exposure(row["exposure_id"], row["group_id"], row["workload_id"],
                                dt(row["first_observed_at"]), row["revision"], dt(row["created_at"]))
                state.exposures[item.exposure_id] = item
                state._exposure_index[(item.group_id, item.workload_id)] = item.exposure_id
            for row in conn.execute(sa.select(occurrences)).mappings():
                exposure = state.exposures.get(row["exposure_id"])
                incarnation = state.incarnations.get(row["incarnation_id"])
                if (exposure is None or incarnation is None
                        or exposure.workload_id != incarnation.workload_id
                        or row["workload_id"] != exposure.workload_id):
                    raise DurableIdentityError("occurrence parentage is inconsistent")
                item = Occurrence(row["occurrence_id"], row["exposure_id"], row["incarnation_id"],
                                  row["component_locator"], dt(row["first_observed_at"]),
                                  dt(row["first_ingested_at"]), row["revision"], dt(row["created_at"]))
                state.occurrences[item.occurrence_id] = item
                if item.component_locator is not None:
                    state._occurrence_index[(item.exposure_id, item.incarnation_id,
                                             item.component_locator)] = item.occurrence_id
            for row in conn.execute(sa.select(source_observations)).mappings():
                if row["occurrence_id"]:
                    if row["occurrence_id"] not in state.occurrences:
                        raise DurableIdentityError("observation references missing occurrence")
                    state.observation_occurrences[row["observation_id"]] = row["occurrence_id"]
            for row in conn.execute(sa.select(identity_rule_definitions)).mappings():
                context_fields = self._stored_context_fields(
                    row["workload_context_fields"], row["workload_match_fields"])
                rule = RuleV1(row["rule_id"], row["rule_version"],
                              tuple(row["workload_match_fields"]),
                              verified_asset_locator=row["verified_asset_locator"],
                              workload_context_fields=context_fields)
                if (self._rule_digest(rule) != row["definition_digest"]
                        or row["authorisation_decision_id"] is None):
                    raise DurableIdentityError("stored rule definition is corrupt")
                config_id = str(uuid.uuid5(uuid.NAMESPACE_URL,
                    f"identity-rule:{rule.rule_id}:{rule.rule_version}:{row['definition_digest']}"))
                decision = conn.execute(sa.select(identity_authorisation_decisions).where(
                    identity_authorisation_decisions.c.decision_id ==
                    row["authorisation_decision_id"])).mappings().first()
                if (decision is None or decision["action"] != "identity.rule_provision"
                        or decision["target_id"] != config_id):
                    raise DurableIdentityError("rule has no matching retained authorisation decision")
                state.rule_definitions[(rule.rule_id, rule.rule_version)] = (
                    rule.workload_match_fields, rule.verified_asset_locator,
                    rule.workload_context_fields)
            corrections = conn.execute(sa.select(correction_records).order_by(
                correction_records.c.record_type, correction_records.c.record_id,
                correction_records.c.previous_revision)).mappings().all()
            by_id = {row["correction_id"]: row for row in corrections}
            for row in corrections:
                bucket = {"group": state.groups, "workload": state.workloads,
                    "incarnation": state.incarnations, "exposure": state.exposures,
                    "occurrence": state.occurrences}.get(row["record_type"])
                if bucket is None or row["record_id"] not in bucket:
                    raise DurableIdentityError("correction references missing target")
                state.corrections.append(CorrectionRecord(
                    correction_id=row["correction_id"], record_type=row["record_type"],
                    record_id=row["record_id"], old_value=row["old_value"],
                    new_value=row["new_value"], actor=row["actor"],
                    reason=row["reason"], correlation_id=row["correlation_id"],
                    affected_record_ids=tuple(row["affected_record_ids"]),
                    created_at=dt(row["created_at"]), field_name=row["field_name"],
                    previous_revision=row["previous_revision"],
                    new_revision=row["new_revision"],
                    assessment_impact=row["assessment_impact"],
                    issue_impact=row["issue_impact"]))
            for group in state.groups.values():
                self._validate_group_chain(group, corrections)
            group_alias_rows = conn.execute(sa.select(group_key_alias_events).order_by(
                    group_key_alias_events.c.event_sequence)).mappings().all()
            for row in group_alias_rows:
                correction = by_id.get(row["correction_id"])
                key = NativeGroupKey(*(row[name] for name in (
                    "source_family", "native_id_scheme", "native_id_authority", "native_id_value")))
                if (correction is None or correction["record_type"] != "group"
                        or correction["record_id"] != row["target_group_id"]):
                    raise DurableIdentityError("group alias has no matching correction")
                if row["action"] == "activate":
                    if state.group_key_aliases.get(key) not in (None, row["target_group_id"]):
                        raise DurableIdentityError("group alias collision")
                    state.group_key_aliases[key] = row["target_group_id"]
                elif row["action"] == "retire" and state.group_key_aliases.get(key) == row["target_group_id"]:
                    del state.group_key_aliases[key]
                else:
                    raise DurableIdentityError("group alias event chain is contradictory")
            for group in state.groups.values():
                self._validate_group_alias_history(group, corrections, group_alias_rows)
            for row in conn.execute(sa.select(mapping_alias_events).order_by(
                    mapping_alias_events.c.event_sequence)).mappings():
                correction = by_id.get(row["correction_id"])
                if (correction is None or correction["record_type"] != row["record_type"]
                        or correction["record_id"] != row["target_record_id"]
                        or correction["field_name"] != row["field_name"]
                        or row["old_value"] != correction[
                            "old_value" if row["action"] == "activate" else "new_value"]):
                    raise DurableIdentityError("mapping alias has no matching correction")
                key = tuple([row["record_type"], row["field_name"]]
                    + [x for x in (row["scope_a"], row["scope_b"]) if x is not None]
                    + [row["old_value"]])
                if row["action"] == "activate":
                    if state.mapping_aliases.get(key) not in (None, row["target_record_id"]):
                        raise DurableIdentityError("mapping alias collision")
                    state.mapping_aliases[key] = row["target_record_id"]
                elif row["action"] == "retire" and state.mapping_aliases.get(key) == row["target_record_id"]:
                    del state.mapping_aliases[key]
                else:
                    raise DurableIdentityError("mapping alias event chain is contradictory")
            mapping_rows = conn.execute(sa.select(mapping_alias_events).order_by(
                mapping_alias_events.c.event_sequence)).mappings().all()
            for record_type in ("workload", "incarnation", "exposure", "occurrence"):
                bucket = getattr(state, f"{record_type}s")
                for record in bucket.values():
                    self._validate_mapping_alias_history(
                        record_type, record, corrections, mapping_rows)
            for key, target in state.mapping_aliases.items():
                state.aliases.setdefault(key[-1], target)
            for row in conn.execute(sa.select(identity_resolutions).order_by(
                    identity_resolutions.c.observation_id, identity_resolutions.c.revision)).mappings():
                state.resolutions.append(IdentityResolutionV1(
                    schema_version=1, resolution_id=row["resolution_id"], revision=row["revision"],
                    observation_id=row["observation_id"], rule_id=row["rule_id"],
                    rule_version=row["rule_version"], matching_inputs=dict(row["matching_inputs"]),
                    candidate_workload_ids=tuple(row["candidate_workload_ids"]), outcome=row["outcome"],
                    evaluated_at=dt(row["evaluated_at"]), group_id=row["group_id"],
                    workload_id=row["workload_id"], incarnation_id=row["incarnation_id"],
                    exposure_id=row["exposure_id"], occurrence_id=row["occurrence_id"],
                    candidate_explanations=tuple(row["candidate_explanations"]), reason=row["reason"],
                    supersedes_resolution_id=row["supersedes_resolution_id"]))
            memberships = set(conn.execute(sa.select(
                exposure_workload_memberships.c.exposure_id,
                exposure_workload_memberships.c.workload_id)).all())
            for exposure in state.exposures.values():
                if (exposure.exposure_id, exposure.workload_id) not in memberships:
                    raise DurableIdentityError("current exposure membership is missing")
            last_by_observation = {}
            for resolution in state.resolutions:
                previous = last_by_observation.get(resolution.observation_id)
                if (resolution.revision != (previous.revision + 1 if previous else 1)
                        or resolution.supersedes_resolution_id != (
                            previous.resolution_id if previous else None)):
                    raise DurableIdentityError("resolution supersession chain is incomplete")
                if (resolution.group_id is not None and resolution.group_id not in state.groups
                        or resolution.workload_id is not None
                        and resolution.workload_id not in state.workloads
                        or resolution.exposure_id is not None
                        and resolution.exposure_id not in state.exposures
                        or resolution.incarnation_id is not None
                        and resolution.incarnation_id not in state.incarnations
                        or resolution.occurrence_id is not None
                        and resolution.occurrence_id not in state.occurrences
                        or any(candidate not in state.workloads
                               for candidate in resolution.candidate_workload_ids)):
                    raise DurableIdentityError("resolution references missing identity records")
                last_by_observation[resolution.observation_id] = resolution
            return state
        finally:
            if owns:
                conn.close()

    @staticmethod
    def _validate_group_chain(group, corrections):
        rows = [r for r in corrections if r["record_type"] == "group"
                and r["record_id"] == group.group_id]
        if len(rows) != group.revision - 1:
            raise DurableIdentityError("group correction history is incomplete")
        state = vars(group.key).copy()
        for expected, row in enumerate(reversed(rows), 1):
            revision = group.revision - expected
            field = row["field_name"]
            if (row["previous_revision"] != revision
                    or row["new_revision"] != revision + 1
                    or field not in state or state[field] != row["new_value"]):
                raise DurableIdentityError("group correction history is contradictory")
            state[field] = row["old_value"]

    @staticmethod
    def _validate_group_alias_history(group, corrections, events):
        rows = sorted((r for r in corrections if r["record_type"] == "group"
                       and r["record_id"] == group.group_id),
                      key=lambda r: r["previous_revision"])
        current = vars(group.key).copy()
        for row in reversed(rows):
            current[row["field_name"]] = row["old_value"]
        aliases = set()
        previous_sequence = 0
        keys = ("source_family", "native_id_scheme", "native_id_authority", "native_id_value")
        for row in rows:
            old_key = NativeGroupKey(**current)
            current[row["field_name"]] = row["new_value"]
            new_key = NativeGroupKey(**current)
            recorded = sorted((e for e in events if e["correction_id"] == row["correction_id"]),
                              key=lambda e: e["event_sequence"])
            expected = []
            if new_key in aliases:
                expected.append(("retire", new_key))
                aliases.remove(new_key)
            expected.append(("activate", old_key))
            aliases.add(old_key)
            if len(recorded) != len(expected):
                raise DurableIdentityError("group alias event history is incomplete")
            for event, (action, key) in zip(recorded, expected):
                if (event["event_sequence"] <= previous_sequence
                        or event["action"] != action
                        or event["target_group_id"] != group.group_id
                        or tuple(event[name] for name in keys) != tuple(vars(key)[name] for name in keys)):
                    raise DurableIdentityError("group alias event history is contradictory")
                previous_sequence = event["event_sequence"]

    @staticmethod
    def _validate_mapping_alias_history(record_type, record, corrections, events):
        """Replay one record's ordered correction chain and require exactly
        the scoped alias activations/retirements it implies, in order.

        A missing, wrong-scope or reordered event would otherwise leave a
        projection that lets a late report create a replacement record."""
        record_id = getattr(record, f"{record_type}_id")
        rows = sorted((r for r in corrections if r["record_type"] == record_type
                       and r["record_id"] == record_id),
                      key=lambda r: r["previous_revision"])
        recorded = [e for e in events if e["target_record_id"] == record_id
                    and e["record_type"] == record_type]
        if not rows:
            # A revised record without any correction row has lost its
            # history even when every alias event is also absent.
            if recorded or record.revision != 1:
                raise DurableIdentityError("mapping correction history is incomplete")
            return
        if len(rows) != record.revision - 1:
            raise DurableIdentityError("mapping correction history is incomplete")
        if record_type == "workload":
            values = dict(record.stable_attrs)
        else:
            values = {name: getattr(record, name) for name in {
                "incarnation": ("workload_id", "host_locator"),
                "exposure": ("group_id", "workload_id"),
                "occurrence": ("exposure_id", "incarnation_id", "component_locator"),
            }[record_type]}
        for expected, row in enumerate(reversed(rows), 1):
            revision = record.revision - expected
            field = row["field_name"]
            if (row["previous_revision"] != revision or row["new_revision"] != revision + 1
                    or field not in values or field == "workload_id" and record_type == "incarnation"
                    or values[field] != row["new_value"]):
                raise DurableIdentityError("mapping correction history is contradictory")
            values[field] = row["old_value"]

        def key(field, value):
            if record_type == "incarnation":
                scope = (values["workload_id"], None)
            elif record_type == "exposure":
                scope = (values["group_id" if field == "workload_id" else "workload_id"], None)
            elif record_type == "occurrence" and field == "component_locator":
                scope = (values["exposure_id"], values["incarnation_id"])
            elif record_type == "occurrence":
                scope = (record_id, None)
            else:
                scope = (None, None)
            return (field, *scope, value)

        active = set()
        previous_sequence = 0
        for row in rows:
            field = row["field_name"]
            expected = []
            new_key = key(field, row["new_value"])
            if row["new_value"] is not None and new_key in active:
                expected.append(("retire", new_key))
                active.remove(new_key)
            if row["old_value"] is not None:
                old_key = key(field, row["old_value"])
                expected.append(("activate", old_key))
                active.add(old_key)
            actual = [e for e in recorded if e["correction_id"] == row["correction_id"]]
            if sorted(expected) != sorted((e["action"], (e["field_name"], e["scope_a"],
                    e["scope_b"], e["old_value"])) for e in actual):
                raise DurableIdentityError("mapping alias event history is incomplete or mis-scoped")
            if any(e["event_sequence"] <= previous_sequence for e in actual):
                raise DurableIdentityError("mapping alias event history is reordered")
            previous_sequence = max((e["event_sequence"] for e in actual),
                                    default=previous_sequence)
            values[field] = row["new_value"]
        if len(recorded) != sum(1 for e in recorded
                                if any(e["correction_id"] == r["correction_id"] for r in rows)):
            raise DurableIdentityError("mapping alias event has no matching correction")

    def correct_group_key(self, correction_request_id, group_id, expected_revision,
                          new_key, at):
        """Authorised single-field native-key correction with historical proof."""
        request_id = _uuid(correction_request_id, "correction_request_id")
        group_id = _uuid(group_id, "group_id")
        at = _utc(at)
        if not isinstance(new_key, NativeGroupKey):
            raise DurableIdentityError("new_key must be a complete NativeGroupKey")
        if type(expected_revision) is not int or expected_revision < 1:
            raise DurableIdentityError("expected_revision must be positive")
        if self.engine.dialect.name == "sqlite":
            conn = self.engine.connect().execution_options(isolation_level="AUTOCOMMIT")
            try:
                conn.exec_driver_sql("BEGIN IMMEDIATE")
                result = self._correct_group_inner(conn, request_id, group_id,
                    expected_revision, new_key, at)
                conn.commit()
                return result
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
        with self.engine.begin() as conn:
            return self._correct_group_inner(conn, request_id, group_id,
                expected_revision, new_key, at)

    def _correct_group_inner(self, conn, request_id, group_id, expected_revision,
                             new_key, at):
        lock_identity_graph(conn)
        query = sa.select(groups).where(groups.c.group_id == group_id)
        if self.engine.dialect.name == "postgresql":
            query = query.with_for_update()
        current = conn.execute(query).mappings().first()
        if current is None or current["revision"] != expected_revision:
            raise DurableIdentityError("group correction target or revision is stale")
        state = self.restore_state(conn)
        old_key = state.groups[group_id].key
        changes = [(field, getattr(old_key, field), getattr(new_key, field))
                   for field in vars(old_key) if getattr(old_key, field) != getattr(new_key, field)]
        if len(changes) != 1 or any(not isinstance(value, str) or not value
                                    for value in vars(new_key).values()):
            raise DurableIdentityError("group correction requires one changed complete key field")
        field, old_value, new_value = changes[0]
        decision = self._authorise(conn, "identity.group_key_correct", group_id,
            {"request_id": request_id, "expected_revision": expected_revision,
             "old_key": vars(old_key), "new_key": vars(new_key)})
        rec = state.record_correction("group", group_id, old_value, new_value,
            decision.principal_id, decision.reason, decision.correlation_id, (), at,
            field_name=field)
        updated = conn.execute(groups.update().where(
            groups.c.group_id == group_id, groups.c.revision == expected_revision).values(
            **vars(new_key), revision=expected_revision + 1))
        if updated.rowcount != 1:
            raise DurableIdentityError("group revision changed during correction")
        conn.execute(correction_records.insert().values(
            correction_id=rec.correction_id, record_type="group", record_id=group_id,
            old_value=old_value, new_value=new_value, actor=decision.principal_id,
            reason=decision.reason, correlation_id=decision.correlation_id,
            affected_record_ids=list(rec.affected_record_ids), created_at=at,
            field_name=field, previous_revision=expected_revision,
            new_revision=expected_revision + 1, assessment_impact="unverified",
            issue_impact="unverified"))
        sequence = conn.execute(sa.select(sa.func.coalesce(sa.func.max(
            group_key_alias_events.c.event_sequence), 0))).scalar_one()
        def alias_event(action, key, sequence):
            conn.execute(group_key_alias_events.insert().values(
                alias_event_id=str(uuid.uuid4()), correction_id=rec.correction_id,
                action=action, **vars(key), target_group_id=group_id,
                evidence_ref=decision.evidence_ref, occurred_at=at,
                event_sequence=sequence))
        if new_key in state.group_key_aliases:
            # record_correction retired this alias from working state; read
            # the persisted projection to distinguish a reversal.
            raise DurableIdentityError("reversal alias projection was not retired")
        active_new = conn.execute(sa.select(group_key_alias_events).where(
            group_key_alias_events.c.source_family == new_key.source_family,
            group_key_alias_events.c.native_id_scheme == new_key.native_id_scheme,
            group_key_alias_events.c.native_id_authority == new_key.native_id_authority,
            group_key_alias_events.c.native_id_value == new_key.native_id_value
        ).order_by(group_key_alias_events.c.event_sequence.desc()).limit(1)).mappings().first()
        if active_new and active_new["action"] == "activate":
            if active_new["target_group_id"] != group_id:
                raise DurableIdentityError("historical native key belongs to another group")
            sequence += 1
            alias_event("retire", new_key, sequence)
        sequence += 1
        alias_event("activate", old_key, sequence)
        reread = self.restore_state(conn)
        if (reread.groups[group_id].key != new_key
                or reread.group_key_aliases.get(old_key) != group_id
                or new_key in reread.group_key_aliases):
            raise DurableIdentityError("group correction readback failed")
        return rec

    def resolve_retained(self, resolution_request_id, observation, retained_observation_revision,
                         pinned_rule, matching_inputs, evaluated_at):
        request_id = _uuid(resolution_request_id, "resolution_request_id")
        evaluated_at = _utc(evaluated_at)
        if isinstance(observation, str):
            observation_id = _uuid(observation, "observation_id")
        else:
            observation_id = _uuid(observation.observation_id, "observation_id")
        if not isinstance(retained_observation_revision, int) or retained_observation_revision < 1:
            raise DurableIdentityError("retained_observation_revision must be positive")
        rule = pinned_rule
        if not isinstance(rule, RuleV1):
            raise DurableIdentityError("pinned_rule must be RuleV1")
        if not isinstance(matching_inputs, dict):
            raise DurableIdentityError("matching_inputs must be an object")
        rule.validate_context(matching_inputs)
        canonical_inputs = json.loads(json.dumps(matching_inputs, sort_keys=True,
            separators=(",", ":"), allow_nan=False))
        if any(type(k) is not str or type(v) is not str for k, v in canonical_inputs.items()):
            raise DurableIdentityError("matching inputs must be string pairs")
        rule.validate_context(canonical_inputs)
        # A supplied DTO may carry unpersisted changes despite identical ID
        # and revision. The transaction compares it to the retained row.
        fingerprint = self._request_fingerprint(
            observation_id=observation_id,
            observation_revision=retained_observation_revision, rule=rule,
            matching_inputs=canonical_inputs, evaluated_at=evaluated_at)
        if self.engine.dialect.name == "sqlite":
            conn = self.engine.connect().execution_options(isolation_level="AUTOCOMMIT")
            try:
                conn.exec_driver_sql("BEGIN IMMEDIATE")
                result = self._resolve_inner(conn, request_id, observation, observation_id,
                                             retained_observation_revision, rule, matching_inputs,
                                             evaluated_at, fingerprint)
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
                return result
            finally:
                conn.close()
        with self.engine.begin() as conn:
            return self._resolve_inner(conn, request_id, observation, observation_id,
                                       retained_observation_revision, rule, matching_inputs,
                                       evaluated_at, fingerprint)

    def _resolve_inner(self, conn, request_id, observation, observation_id, obs_revision,
                       rule, matching_inputs, evaluated_at, fingerprint):
        lock_identity_graph(conn)
        observation_query = sa.select(source_observations).where(
            source_observations.c.observation_id == observation_id)
        if self.engine.dialect.name == "postgresql":
            # Assessment reconciliation takes this same row lock before it
            # snapshots the current resolution head. A rerun cannot append a
            # new head between proof validation and guarded assessment commit.
            observation_query = observation_query.with_for_update()
        row = conn.execute(observation_query).mappings().first()
        if row is None:
            raise DurableIdentityError("retained observation not found")
        retained = _row_to_observation(row)
        if retained.revision != obs_revision:
            raise DurableIdentityError("retained observation revision does not match persisted row")
        if (not isinstance(observation, str)
                and (observation.observation_id != retained.observation_id
                     or _ingest_fields(observation) != _ingest_fields(retained))):
            raise DurableIdentityError("supplied observation differs from retained content")
        observation = retained
        prior_resolution = conn.execute(sa.select(identity_resolutions).where(
            identity_resolutions.c.observation_id == observation_id
        ).order_by(identity_resolutions.c.revision.desc()).limit(1)).mappings().first()
        prior_request = conn.execute(sa.select(identity_resolution_requests).where(
            identity_resolution_requests.c.resolution_request_id == request_id)).mappings().first()
        rules = identity_rule_definitions
        digest = self._rule_digest(rule)
        stored = conn.execute(sa.select(rules).where(
            rules.c.rule_id == rule.rule_id, rules.c.rule_version == rule.rule_version)).mappings().first()
        if stored and stored["definition_digest"] != digest:
            raise DurableIdentityError("immutable rule definition changed")
        if not stored:
            raise DurableIdentityError("rule definition has not been provisioned")
        stored_context_fields = self._stored_context_fields(
            stored["workload_context_fields"], stored["workload_match_fields"])
        if tuple(stored["workload_match_fields"]) != rule.workload_match_fields \
                or stored_context_fields != rule.workload_context_fields \
                or stored["verified_asset_locator"] != rule.verified_asset_locator:
            raise DurableIdentityError("stored rule definition is inconsistent")
        state = self.restore_state(conn)
        correction_mode = (prior_request["authorisation_decision_id"] is not None
                           if prior_request else prior_resolution is not None)
        decision = None
        if correction_mode:
            prior_id = (conn.execute(sa.select(
                identity_resolutions.c.supersedes_resolution_id).where(
                identity_resolutions.c.resolution_id == prior_request["resolution_id"]
            )).scalar_one() if prior_request else prior_resolution["resolution_id"])
            decision = self._authorise(conn, "identity.reresolve", observation_id,
                {"request_id": request_id, "prior_resolution_id": prior_id},
                persist=False)
            # Bind the semantic authorisation only. A trusted evaluator may
            # issue a fresh decision ID, time and audit references for an
            # exact resend; those are evaluation metadata, not request input.
            fingerprint = hashlib.sha256((fingerprint + self._decision_semantics(
                decision)).encode()).hexdigest()
        if prior_request:
            if prior_request["request_fingerprint"] != fingerprint:
                raise ResolutionRequestConflict("resolution request ID was reused with changed inputs")
            if decision is not None:
                retained_decision = conn.execute(sa.select(
                    *(sa.cast(column, sa.Text).label(column.name)
                      if column.name == "decision_details" else column
                      for column in identity_authorisation_decisions.c)).where(
                    identity_authorisation_decisions.c.decision_id ==
                    prior_request["authorisation_decision_id"])).mappings().first()
                if not self._retained_decision_matches(retained_decision, decision):
                    raise DurableIdentityError(
                        "retained authorisation decision does not match the correction request")
            return self._resolution_store._read_v2_row(conn, conn.execute(
                self._resolution_store._v2_select().where(
                    identity_resolutions.c.resolution_id == prior_request["resolution_id"])).mappings().one())
        prior = state.resolution_for_observation(observation_id)
        if correction_mode:
            self._authorise(conn, "identity.reresolve", observation_id,
                {"request_id": request_id, "prior_resolution_id": prior.resolution_id},
                decision=decision)
            # The old observation link is historical evidence.  Remove only
            # the working-state index so the resolver can append a reviewed
            # superseding result; no persisted row or source link is deleted.
            state.observation_occurrences.pop(observation_id, None)
        before = ({gid: set(g.cve_refs) for gid, g in state.groups.items()},
                  set(state.workloads), set(state.incarnations),
                  set(state.exposures), set(state.occurrences))
        result_v1 = resolve(state, observation, rule, dict(matching_inputs), evaluated_at)
        self._persist_new_graph(conn, state, before, evaluated_at)
        group_revision = None
        if result_v1.outcome == "unresolved" and result_v1.group_id:
            group_query = sa.select(groups).where(groups.c.group_id == result_v1.group_id)
            if self.engine.dialect.name == "postgresql":
                group_query = group_query.with_for_update()
            group_row = conn.execute(group_query).mappings().one()
            if tuple(group_row[name] for name in ("source_family", "native_id_scheme",
                    "native_id_authority", "native_id_value")) != (
                    observation.source_family, observation.native_id_scheme,
                    observation.native_id_authority, observation.native_id_value):
                raise DurableIdentityError("group key differs from retained observation")
            group_revision = group_row["revision"]
        # The resolver may report the workload whose historical alias blocked
        # selection. V2 retains that evidence in candidates/explanations; a
        # non-selected outcome carries no selected membership.
        selected = result_v1.outcome in ("matched", "new")
        result = IdentityResolutionV2(
            schema_version=2, resolution_id=result_v1.resolution_id, revision=result_v1.revision,
            observation_id=result_v1.observation_id, rule_id=result_v1.rule_id,
            rule_version=result_v1.rule_version, matching_inputs=result_v1.matching_inputs,
            candidate_workload_ids=result_v1.candidate_workload_ids, outcome=result_v1.outcome,
            evaluated_at=result_v1.evaluated_at, group_id=result_v1.group_id,
            workload_id=result_v1.workload_id if selected else None,
            incarnation_id=result_v1.incarnation_id if selected else None,
            exposure_id=result_v1.exposure_id if selected else None,
            occurrence_id=result_v1.occurrence_id if selected else None,
            candidate_explanations=result_v1.candidate_explanations, reason=result_v1.reason,
            supersedes_resolution_id=result_v1.supersedes_resolution_id,
            selected_exposure_revision=(conn.execute(sa.select(exposures.c.revision).where(
                exposures.c.exposure_id == result_v1.exposure_id)).scalar_one()
                                        if result_v1.exposure_id else None),
            selected_occurrence_revision=(conn.execute(sa.select(occurrences.c.revision).where(
                occurrences.c.occurrence_id == result_v1.occurrence_id)).scalar_one()
                                          if result_v1.occurrence_id else None),
            known_group_revision=group_revision)
        values = self._resolution_store._v2_values(result)
        self._resolution_store._write_v2_inner(conn, result, values)
        if result.occurrence_id:
            conn.execute(source_observations.update().where(
                source_observations.c.observation_id == observation_id).values(
                    occurrence_id=result.occurrence_id))
            if result.exposure_id and result.group_id:
                from uvm.assessment.episodes import record_positive_observation
                record_positive_observation(conn, group_id=result.group_id,
                    exposure_id=result.exposure_id, occurrence_id=result.occurrence_id,
                    observation_id=observation_id, observed_at=observation.observed_at,
                    collection_status=observation.collection_status,
                    resolution_reliable=result.outcome in {"matched", "new"},
                    now=evaluated_at)
                # Persist the immutable first UVM retention receipt in the same
                # transaction as the retained positive and episode membership.
                episode = conn.execute(sa.select(exposure_episodes).where(
                    exposure_episodes.c.exposure_id == result.exposure_id,
                    exposure_episodes.c.is_current.is_(True))).mappings().first()
                membership = (conn.execute(sa.select(exposure_episode_members.c.occurrence_id).where(
                    exposure_episode_members.c.episode_id == episode["episode_id"],
                    exposure_episode_members.c.occurrence_id == result.occurrence_id)).first()
                    if episode else None)
                if episode and membership:
                    retention_receipt = conn.execute(sa.select(source_observation_receipts).where(
                        source_observation_receipts.c.source_observation_id == observation_id,
                        source_observation_receipts.c.source_account_id == observation.source_account_id,
                        source_observation_receipts.c.run_id == observation.run_id,
                        source_observation_receipts.c.source_record_ordinal ==
                            observation.source_record_ordinal)).mappings().first()
                    # Choose by durable retention order, not resolution order.
                    # A successor only accepts positives newer than the preceding
                    # episode's confirmation, so an old receipt cannot restart it.
                    prior_confirmation = conn.execute(sa.select(sa.func.max(sa.func.coalesce(
                        exposure_episode_members.c.confirmed_at, exposure_episode_members.c.original_confirmed_at)))
                        .select_from(exposure_episode_members.join(exposure_episodes,
                            exposure_episode_members.c.episode_id == exposure_episodes.c.episode_id)).where(
                        exposure_episodes.c.exposure_id == result.exposure_id,
                        exposure_episodes.c.episode_number < episode["episode_number"],
                        exposure_episode_members.c.occurrence_id == result.occurrence_id)).scalar_one_or_none()
                    causal_membership = source_observations.c.occurrence_id == result.occurrence_id
                    # A locator is not proof of the rule's workload match fields.
                    # Only observations already resolved to this exact occurrence
                    # can contribute a causal receipt. Unresolved rows retain their
                    # uncertainty until an authorised resolution/correction.
                    causal_query = sa.select(source_observation_receipts).select_from(
                        source_observation_receipts.join(source_observations,
                            source_observation_receipts.c.source_observation_id == source_observations.c.observation_id)).where(
                        causal_membership,
                        source_observations.c.collection_status != "failed",
                        source_observations.c.ingest_outcome == "created")
                    if prior_confirmation is not None:
                        causal_query = causal_query.where(source_observations.c.observed_at > prior_confirmation)
                    causal_receipt = conn.execute(causal_query.order_by(
                        source_observation_receipts.c.retained_at,
                        source_observations.c.retention_order).limit(1)).mappings().first()
                    retention_receipt = causal_receipt
                    prior_receipt = conn.execute(sa.select(sla_ingest_receipts).where(
                        sla_ingest_receipts.c.episode_id == episode["episode_id"],
                        sla_ingest_receipts.c.occurrence_id == result.occurrence_id)).mappings().first()
                    if prior_receipt is None and retention_receipt is not None:
                        conn.execute(sla_ingest_receipts.insert().values(
                            receipt_id=str(uuid.uuid4()),
                            retention_receipt_id=retention_receipt["receipt_id"],
                            episode_id=episode["episode_id"],
                            occurrence_id=result.occurrence_id,
                            ingested_at=retention_receipt["retained_at"],
                            source_observation_id=retention_receipt["source_observation_id"],
                            source_observed_at=retention_receipt["source_observed_at"],
                            source_collected_at=retention_receipt["source_collected_at"],
                            ingest_operation_id=retention_receipt["retention_operation_id"],
                            policy_id=None, policy_version=None,
                            created_at=evaluated_at))
                    pinned = conn.execute(sa.select(sla_episode_contracts.c.episode_id).where(
                        sla_episode_contracts.c.episode_id == episode["episode_id"])).first()
                    if pinned is None and retention_receipt is not None:
                        policy_rows = [dict(row) for row in conn.execute(sa.select(sla_policy_versions).where(
                            sla_policy_versions.c.created_at <= retention_receipt["retained_at"])
                            .order_by(sla_policy_versions.c.revision)).mappings().all()
                            if row["document"].get("start_source") == "uvm_ingest_commit_v1"]
                        context = (conn.execute(sa.select(workloads.c.stable_attrs).where(
                            workloads.c.workload_id == result.workload_id)).scalar_one_or_none() or {})
                        from uvm.assessment.sla_classification import select_reset_policy
                        selected_policy, _reason = select_reset_policy(policy_rows,
                            episode["group_id"], context, retention_receipt["retained_at"],
                            policy_scope_matches=lambda document, attrs: all(
                                not document.get("scope", {}).get(key)
                                or attrs.get(value) in document["scope"][key]
                                for key, value in (("environments", "environment"),
                                    ("service_ids", "service_id"))))
                        legacy_positive = conn.execute(sa.select(source_observations.c.observation_id)
                            .select_from(source_observations.outerjoin(source_observation_receipts,
                                source_observation_receipts.c.source_observation_id == source_observations.c.observation_id))
                            .where(source_observations.c.occurrence_id == result.occurrence_id,
                                source_observation_receipts.c.receipt_id.is_(None)).limit(1)).first()
                        if int(episode["episode_number"]) == 1 and legacy_positive:
                            selected_policy = None
                        is_g7 = selected_policy is not None
                        conn.execute(sla_episode_contracts.insert().values(
                            episode_id=episode["episode_id"], contract_version=7 if is_g7 else 5,
                            start_source=("uvm_ingest_commit_v1" if is_g7 else "source_observation_v1"),
                            retention_receipt_id=retention_receipt["receipt_id"],
                            policy_id=selected_policy["policy_id"] if is_g7 else None,
                            policy_version=selected_policy["version"] if is_g7 else None,
                            pinned_at=retention_receipt["retained_at"], created_at=evaluated_at))
                    contract = conn.execute(sa.select(sla_episode_contracts).where(
                        sla_episode_contracts.c.episode_id == episode["episode_id"])).mappings().first()
                    if contract and contract["contract_version"] == 7:
                        if (prior_receipt is not None and retention_receipt is not None
                                and retention_receipt["retained_at"] < prior_receipt["ingested_at"]):
                            from uvm.assessment.g7_clock import record_earlier_proven_receipt_gap
                            record_earlier_proven_receipt_gap(conn,
                                episode_id=episode["episode_id"], occurrence_id=result.occurrence_id,
                                original_receipt=prior_receipt, earlier_receipt=retention_receipt,
                                resolution_id=result.resolution_id,
                                authorisation_decision_id=decision.decision_id if decision else None,
                                known_at=evaluated_at)
                        # Materialise the G7 head with retained provenance while
                        # binding exact episode membership, never from a report.
                        from uvm.assessment.g7_clock import ensure_current_evaluation
                        ensure_current_evaluation(conn, episode_id=episode["episode_id"],
                            occurrence_id=result.occurrence_id, known_at=evaluated_at)
        conn.execute(identity_resolution_requests.insert().values(
            resolution_request_id=request_id, observation_id=observation_id,
            observation_revision=obs_revision, request_fingerprint=fingerprint,
            authorisation_decision_id=decision.decision_id if decision else None,
            resolution_id=result.resolution_id, resolution_revision=result.revision,
            created_at=evaluated_at))
        return result

    def _persist_new_graph(self, conn, state, before, at):
        lock_identity_graph(conn)
        groups_before, workloads_before, inc_before, exp_before, occ_before = before
        for item in state.groups.values():
            if item.group_id not in groups_before:
                conn.execute(groups.insert().values(group_id=item.group_id,
                    source_family=item.key.source_family, native_id_scheme=item.key.native_id_scheme,
                    native_id_authority=item.key.native_id_authority, native_id_value=item.key.native_id_value,
                    revision=item.revision, created_at=item.created_at or at))
                for cve in item.cve_refs:
                    conn.execute(group_cve_refs.insert().values(group_id=item.group_id, cve_ref=cve))
            else:
                for cve in item.cve_refs - groups_before[item.group_id]:
                    conn.execute(group_cve_refs.insert().values(group_id=item.group_id, cve_ref=cve))
        for item in state.workloads.values():
            if item.workload_id not in workloads_before:
                conn.execute(workloads.insert().values(workload_id=item.workload_id,
                    stable_attrs=item.stable_attrs, revision=item.revision, created_at=item.created_at or at))
        for item in state.incarnations.values():
            if item.incarnation_id not in inc_before:
                conn.execute(incarnations.insert().values(**{k: getattr(item, k) for k in
                    ("incarnation_id", "workload_id", "host_locator", "image_ref",
                     "first_observed_at", "revision", "created_at")}))
        for item in state.exposures.values():
            if item.exposure_id not in exp_before:
                conn.execute(exposures.insert().values(**{k: getattr(item, k) for k in
                    ("exposure_id", "group_id", "workload_id", "first_observed_at", "revision", "created_at")}))
                conn.execute(exposure_workload_memberships.insert().values(
                    exposure_id=item.exposure_id, workload_id=item.workload_id))
        for item in state.occurrences.values():
            if item.occurrence_id not in occ_before:
                request = OccurrenceCreate(
                    occurrence_id=item.occurrence_id, exposure_id=item.exposure_id,
                    incarnation_id=item.incarnation_id,
                    workload_id=state.incarnations[item.incarnation_id].workload_id,
                    component_locator=item.component_locator,
                    first_observed_at=item.first_observed_at,
                    first_ingested_at=item.first_ingested_at, revision=item.revision,
                    created_at=item.created_at or at)
                values = self._occurrence_store._validate(request)
                self._occurrence_store._write_inner(conn, request, values)


DurableIdentityRepository = IdentityRepository
