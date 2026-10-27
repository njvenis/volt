"""G1 durable CE operation reservation metadata.

This is storage only: no HTTP writer, DefectDojo table, or manifest
membership validator is defined here.  Requests are immutable by writer
contract; state is the current mutable projection and transitions retain
revisioned evidence.  SQL constraints provide shape, identity, and active
reservation collisions, but do not enforce append-only writes or exhaustive
manifest membership.
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger, Boolean, CheckConstraint, Column, DateTime, ForeignKey,
    ForeignKeyConstraint, Index, Integer, JSON, PrimaryKeyConstraint,
    String, Table, UniqueConstraint, Uuid,
)

from uvm.persistence.schema import uvm_metadata

_ID = Uuid(as_uuid=False)
_TZ = DateTime(timezone=True)
_STATUSES = "status IN ('pending', 'settled', 'failed', 'quarantined', 'conflict')"
_REQUEST_KINDS = "request_kind IN ('import', 'reimport')"


def _hex64(column: str, name: str, *, nullable: bool = False):
    sqlite_expression = f"length({column}) = 64 AND {column} NOT GLOB '*[^0-9A-Fa-f]*'"
    postgres_expression = f"{column} ~ '^[0-9A-Fa-f]{{64}}$'"
    if nullable:
        sqlite_expression = f"{column} IS NULL OR ({sqlite_expression})"
    return (
        CheckConstraint(sqlite_expression, name=name).ddl_if(dialect="sqlite"),
        CheckConstraint(postgres_expression, name=name).ddl_if(dialect="postgresql"),
    )

ce_context_registrations = Table(
    "ce_context_registrations", uvm_metadata,
    Column("registration_id", _ID, primary_key=True),
    Column("schema_version", Integer, nullable=False),
    Column("deployment_key", String, nullable=False),
    Column("context_key", String, nullable=False),
    Column("product_id", Integer, nullable=False),
    Column("engagement_id", Integer, nullable=False),
    Column("test_id", Integer, nullable=True),
    UniqueConstraint("registration_id", "deployment_key",
                     name="uq_ce_context_registrations_id_deployment"),
    UniqueConstraint("deployment_key", "context_key",
                     name="uq_ce_context_registrations_deployment_context"),
    CheckConstraint("schema_version = 1",
                    name="ce_context_registrations_schema_version_v1"),
    CheckConstraint("length(deployment_key) > 0",
                    name="ce_context_registrations_deployment_non_empty"),
    CheckConstraint("length(context_key) > 0",
                    name="ce_context_registrations_context_non_empty"),
    CheckConstraint("product_id > 0",
                    name="ce_context_registrations_product_positive"),
    CheckConstraint("engagement_id > 0",
                    name="ce_context_registrations_engagement_positive"),
    CheckConstraint("test_id IS NULL OR test_id > 0",
                    name="ce_context_registrations_test_positive"),
    Index("uq_ce_context_registrations_deployment_test", "deployment_key", "test_id", unique=True,
          sqlite_where=(Column("test_id", Integer).is_not(None)),
          postgresql_where=(Column("test_id", Integer).is_not(None))),
)

ce_deployment_configurations = Table(
    "ce_deployment_configurations", uvm_metadata,
    Column("configuration_id", _ID, primary_key=True),
    Column("schema_version", Integer, nullable=False),
    Column("deployment_key", String, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("ce_base_url", String, nullable=False),
    Column("ce_release", String, nullable=False),
    Column("config_ref", String, nullable=False),
    Column("config_sha256", String, nullable=False),
    Column("recorded_at", _TZ, nullable=False),
    UniqueConstraint("deployment_key", "revision",
                     name="uq_ce_deployment_configurations_deployment_revision"),
    CheckConstraint("schema_version = 1",
                    name="ce_deployment_configurations_schema_version_v1"),
    CheckConstraint("length(deployment_key) > 0",
                    name="ce_deployment_configurations_deployment_non_empty"),
    CheckConstraint("revision > 0",
                    name="ce_deployment_configurations_revision_positive"),
    CheckConstraint("length(ce_base_url) > 0",
                    name="ce_deployment_configurations_base_url_non_empty"),
    CheckConstraint("length(ce_release) > 0",
                    name="ce_deployment_configurations_release_non_empty"),
    CheckConstraint("length(config_ref) > 0",
                    name="ce_deployment_configurations_ref_non_empty"),
    *_hex64("config_sha256", "ce_deployment_configurations_digest_sha256"),
)

ce_context_verifications = Table(
    "ce_context_verifications", uvm_metadata,
    Column("verification_id", _ID, primary_key=True),
    Column("schema_version", Integer, nullable=False),
    Column("registration_id", _ID, nullable=False),
    Column("deployment_key", String, nullable=False),
    Column("deployment_config_revision", Integer, nullable=False),
    Column("product_body_ref", String, nullable=False),
    Column("product_body_sha256", String, nullable=False),
    Column("engagement_body_ref", String, nullable=False),
    Column("engagement_body_sha256", String, nullable=False),
    Column("test_body_ref", String, nullable=True),
    Column("test_body_sha256", String, nullable=True),
    Column("verified_at", _TZ, nullable=False),
    ForeignKeyConstraint(
        ["registration_id", "deployment_key"],
        ["ce_context_registrations.registration_id", "ce_context_registrations.deployment_key"],
        name="fk_ce_context_verifications_registration_deployment",
    ),
    ForeignKeyConstraint(
        ["deployment_key", "deployment_config_revision"],
        ["ce_deployment_configurations.deployment_key", "ce_deployment_configurations.revision"],
        name="fk_ce_context_verifications_deployment_configuration",
    ),
    UniqueConstraint("registration_id", "deployment_config_revision",
                     name="uq_ce_context_verifications_registration_revision"),
    UniqueConstraint("registration_id", "verification_id",
                     name="uq_ce_context_verifications_registration_verification"),
    CheckConstraint("schema_version = 1",
                    name="ce_context_verifications_schema_version_v1"),
    CheckConstraint("length(deployment_key) > 0",
                    name="ce_context_verifications_deployment_non_empty"),
    CheckConstraint("deployment_config_revision > 0",
                    name="ce_context_verifications_config_revision_positive"),
    CheckConstraint("length(product_body_ref) > 0 AND length(engagement_body_ref) > 0",
                    name="ce_context_verifications_required_refs_non_empty"),
    *_hex64("product_body_sha256", "ce_context_verifications_product_digest_sha256"),
    *_hex64("engagement_body_sha256", "ce_context_verifications_engagement_digest_sha256"),
    CheckConstraint("(test_body_ref IS NULL) = (test_body_sha256 IS NULL)",
                    name="ce_context_verifications_test_ref_digest_pair"),
    CheckConstraint("test_body_ref IS NULL OR length(test_body_ref) > 0",
                    name="ce_context_verifications_test_ref_non_empty"),
    *_hex64("test_body_sha256", "ce_context_verifications_test_digest_sha256", nullable=True),
)

ce_context_test_bindings = Table(
    "ce_context_test_bindings", uvm_metadata,
    Column("binding_id", _ID, primary_key=True),
    Column("schema_version", Integer, nullable=False),
    Column("registration_id", _ID, nullable=False),
    Column("originating_operation_id", _ID, nullable=False),
    Column("deployment_key", String, nullable=False),
    Column("test_id", Integer, nullable=False),
    Column("test_body_ref", String, nullable=False),
    Column("test_body_sha256", String, nullable=False),
    Column("deployment_config_revision", Integer, nullable=False),
    Column("bound_at", _TZ, nullable=False),
    ForeignKeyConstraint(
        ["registration_id", "deployment_key"],
        ["ce_context_registrations.registration_id", "ce_context_registrations.deployment_key"],
        name="fk_ce_context_test_bindings_registration_deployment",
    ),
    ForeignKeyConstraint(
        ["originating_operation_id", "registration_id"],
        ["engine_operation_requests.operation_id", "engine_operation_requests.registration_id"],
        name="fk_ce_context_test_bindings_operation_registration",
    ),
    ForeignKeyConstraint(
        ["deployment_key", "deployment_config_revision"],
        ["ce_deployment_configurations.deployment_key", "ce_deployment_configurations.revision"],
        name="fk_ce_context_test_bindings_deployment_configuration",
    ),
    UniqueConstraint("registration_id", name="uq_ce_context_test_bindings_registration"),
    UniqueConstraint("originating_operation_id", name="uq_ce_context_test_bindings_operation"),
    UniqueConstraint("deployment_key", "test_id",
                     name="uq_ce_context_test_bindings_deployment_test"),
    CheckConstraint("schema_version = 1",
                    name="ce_context_test_bindings_schema_version_v1"),
    CheckConstraint("length(deployment_key) > 0",
                    name="ce_context_test_bindings_deployment_non_empty"),
    CheckConstraint("test_id > 0",
                    name="ce_context_test_bindings_test_positive"),
    CheckConstraint("deployment_config_revision > 0",
                    name="ce_context_test_bindings_config_revision_positive"),
    CheckConstraint("length(test_body_ref) > 0",
                    name="ce_context_test_bindings_test_ref_non_empty"),
    *_hex64("test_body_sha256", "ce_context_test_bindings_test_digest_sha256"),
)

engine_operation_requests = Table(
    "engine_operation_requests", uvm_metadata,
    Column("operation_id", _ID, primary_key=True),
    Column("schema_version", Integer, nullable=False),
    Column("context_key", String, nullable=False),
    Column("registration_id", _ID,
           ForeignKey("ce_context_registrations.registration_id"), nullable=True),
    Column("verification_id", _ID,
           nullable=True),
    Column("source_run_id", String, nullable=False),
    Column("scan_type", String, nullable=False),
    Column("payload_sha256", String, nullable=False),
    Column("parser_config_version", String, nullable=False),
    Column("engine_release", String, nullable=False),
    Column("request_kind", String, nullable=False),
    Column("requested_at", _TZ, nullable=False),
    Column("close_old_findings", Boolean, nullable=False),
    Column("test_id", String, nullable=True),
    ForeignKeyConstraint(
        ["registration_id", "verification_id"],
        ["ce_context_verifications.registration_id", "ce_context_verifications.verification_id"],
        name="fk_engine_operation_requests_registration_verification",
    ),
    UniqueConstraint("operation_id", "registration_id",
                     name="uq_engine_operation_requests_operation_registration"),
    CheckConstraint("schema_version > 0", name="engine_operation_requests_schema_version_positive"),
    CheckConstraint(_REQUEST_KINDS, name="engine_operation_requests_request_kind_known"),
    CheckConstraint("close_old_findings = false",
                    name="engine_operation_requests_close_old_findings_false"),
    CheckConstraint("verification_id IS NULL OR registration_id IS NOT NULL",
                    name="engine_operation_requests_verification_registration_pair"),
    CheckConstraint(
        "request_kind <> 'reimport' OR (test_id IS NOT NULL AND length(test_id) > 0)",
        name="engine_operation_requests_reimport_test_required",
    ),
)

engine_operation_manifests = Table(
    "engine_operation_manifests", uvm_metadata,
    Column("operation_id", _ID, ForeignKey("engine_operation_requests.operation_id"), primary_key=True),
    Column("manifest_sha256", String, nullable=False, unique=True),
    Column("manifest_ref", String, nullable=False),
    Column("bound_at", _TZ, nullable=False),
    CheckConstraint("length(manifest_sha256) > 0", name="engine_operation_manifests_digest_non_empty"),
    CheckConstraint("length(manifest_ref) > 0", name="engine_operation_manifests_ref_non_empty"),
)

engine_operation_states = Table(
    "engine_operation_states", uvm_metadata,
    Column("operation_id", _ID, ForeignKey("engine_operation_requests.operation_id"), primary_key=True),
    Column("context_key", String, nullable=False),
    Column("test_id", String, nullable=True),
    Column("bound_test_id", String, nullable=True),
    Column("revision", Integer, nullable=False),
    Column("status", String, nullable=False),
    Column("response_deduplication_complete", Boolean, nullable=True),
    Column("response_ref", String, nullable=True),
    Column("response_test_id", String, nullable=True),
    Column("deduplication_complete", Boolean, nullable=True),
    Column("deduplication_evidence_ref", String, nullable=True),
    Column("settle_readback_ref", String, nullable=True),
    Column("reconciliation_evidence_ref", String, nullable=True),
    Column("first_import_baseline_ref", String, nullable=True),
    Column("finding_ids", JSON, nullable=False),
    Column("endpoint_ids", JSON, nullable=False),
    Column("mapping_revision", Integer, nullable=True),
    Column("prior_mapping_revision", Integer, nullable=True),
    Column("error_code", String, nullable=True),
    Column("error_detail_ref", String, nullable=True),
    Column("supersedes_operation_id", _ID, ForeignKey("engine_operation_requests.operation_id"), nullable=True),
    Column("post_issued", Boolean, nullable=False),
    Column("reconciled", Boolean, nullable=False),
    Column("changed_at", _TZ, nullable=False),
    CheckConstraint("revision > 0", name="engine_operation_states_revision_positive"),
    CheckConstraint(_STATUSES, name="engine_operation_states_status_known"),
    CheckConstraint("mapping_revision IS NULL OR mapping_revision > 0", name="engine_operation_states_mapping_revision_positive"),
    CheckConstraint("prior_mapping_revision IS NULL OR prior_mapping_revision > 0", name="engine_operation_states_prior_mapping_revision_positive"),
    CheckConstraint("test_id IS NULL OR length(test_id) > 0", name="engine_operation_states_test_non_empty"),
    CheckConstraint("bound_test_id IS NULL OR length(bound_test_id) > 0", name="engine_operation_states_bound_test_non_empty"),
    Index("ix_engine_operation_states_context", "context_key"),
    Index("ix_engine_operation_states_test", "test_id"),
    Index("ix_engine_operation_states_bound_test", "bound_test_id"),
)

# Only active reservations collide.  Settled history is retained for
# reconciliation and audit.  The future writer must keep the denormalised
# reservation fields consistent with the immutable request row atomically.
_ACTIVE = "status IN ('pending', 'quarantined', 'conflict')"
Index("uq_engine_operation_states_active_context", engine_operation_states.c.context_key,
      unique=True, sqlite_where=CheckConstraint(_ACTIVE).sqltext,
      postgresql_where=CheckConstraint(_ACTIVE).sqltext)
Index("uq_engine_operation_states_active_test", engine_operation_states.c.test_id,
      unique=True, sqlite_where=CheckConstraint(_ACTIVE + " AND test_id IS NOT NULL").sqltext,
      postgresql_where=CheckConstraint(_ACTIVE + " AND test_id IS NOT NULL").sqltext)

engine_operation_transitions = Table(
    "engine_operation_transitions", uvm_metadata,
    Column("transition_id", _ID, primary_key=True),
    Column("operation_id", _ID, ForeignKey("engine_operation_requests.operation_id"), nullable=False),
    Column("from_revision", Integer, nullable=True),
    Column("to_revision", Integer, nullable=False),
    Column("from_status", String, nullable=True),
    Column("to_status", String, nullable=False),
    Column("evidence_ref", String, nullable=False),
    Column("occurred_at", _TZ, nullable=False),
    Column("transition_reason", String, nullable=False),
    CheckConstraint("from_revision IS NULL OR from_revision > 0", name="engine_operation_transitions_from_revision_positive"),
    CheckConstraint("to_revision > 0", name="engine_operation_transitions_to_revision_positive"),
    CheckConstraint("from_status IS NULL OR " + _STATUSES.replace("status", "from_status"), name="engine_operation_transitions_from_status_known"),
    CheckConstraint(_STATUSES.replace("status", "to_status"), name="engine_operation_transitions_to_status_known"),
    CheckConstraint("from_revision IS NULL OR to_revision > from_revision", name="engine_operation_transitions_revision_increases"),
    CheckConstraint("length(evidence_ref) > 0", name="engine_operation_transitions_evidence_non_empty"),
    CheckConstraint("length(transition_reason) > 0", name="engine_operation_transitions_reason_non_empty"),
    Index("uq_engine_operation_transitions_operation_revision", "operation_id", "to_revision", unique=True),
)

# Durable per-operation occurrence associations published only in the same
# transaction that settles the matching engine mapping.  Raw supported-API
# bytes remain in the content-addressed artifact store; the reference and
# digest bind every row to that immutable read-back.
engine_occurrence_links = Table(
    "engine_occurrence_links", uvm_metadata,
    Column("link_id", _ID, primary_key=True),
    Column("operation_id", _ID,
           ForeignKey("engine_operation_requests.operation_id"), nullable=False),
    Column("manifest_id", _ID,
           ForeignKey("manifest_ledger_headers.manifest_id"), nullable=False),
    Column("mapping_revision", Integer, nullable=False),
    Column("occurrence_id", _ID,
           ForeignKey("occurrences.occurrence_id"), nullable=False),
    Column("test_id", Integer, nullable=False),
    Column("finding_id", Integer, nullable=False),
    Column("endpoint_id", Integer, nullable=True),
    Column("component_name", String, nullable=True),
    Column("component_version", String, nullable=True),
    Column("readback_ref", String, nullable=False),
    Column("readback_sha256", String, nullable=False),
    Column("recorded_at", _TZ, nullable=False),
    UniqueConstraint(
        "operation_id", "mapping_revision", "occurrence_id", "finding_id",
        "endpoint_id", "component_name", "component_version",
        name="uq_engine_occurrence_links_mapping_pair",
    ),
    CheckConstraint("mapping_revision > 0",
                    name="engine_occurrence_links_mapping_revision_positive"),
    CheckConstraint("test_id > 0", name="engine_occurrence_links_test_positive"),
    CheckConstraint("finding_id > 0", name="engine_occurrence_links_finding_positive"),
    CheckConstraint("endpoint_id IS NULL OR endpoint_id > 0",
                    name="engine_occurrence_links_endpoint_positive"),
    CheckConstraint("length(readback_ref) > 0",
                    name="engine_occurrence_links_readback_ref_non_empty"),
    *_hex64("readback_sha256", "engine_occurrence_links_readback_sha256"),
)

ALL_ENGINE_OPERATION_TABLES = (
    ce_context_registrations,
    ce_deployment_configurations, ce_context_verifications,
    ce_context_test_bindings,
    engine_operation_requests, engine_operation_manifests,
    engine_operation_states, engine_operation_transitions,
)

# Additive 0006 manifest ledger.  These tables are deliberately separate from
# ``engine_operation_manifests``: 0005's digest/reference rows remain valid
# historical reservations and are not treated as manifest bodies.
manifest_ledger_headers = Table(
    "manifest_ledger_headers", uvm_metadata,
    Column("manifest_id", _ID, primary_key=True),
    Column("operation_id", _ID, ForeignKey("engine_operation_requests.operation_id"),
           nullable=False, unique=True),
    Column("schema_version", Integer, nullable=False),
    Column("source_family", String, nullable=False),
    Column("source_account_id", String, nullable=False),
    Column("run_id", String, nullable=False),
    Column("context_key", String, nullable=False),
    Column("bound_test_id", String, nullable=True),
    Column("inventory_seal_ref", String, nullable=False),
    Column("inventory_high_watermark", BigInteger, nullable=False),
    Column("retained_row_count", BigInteger, nullable=False),
    Column("conflict_holder_count", BigInteger, nullable=False),
    Column("payload_sha256", String, nullable=False),
    Column("manifest_sha256", String, nullable=False, unique=True),
    Column("sealed_at", _TZ, nullable=False),
    CheckConstraint("schema_version = 1", name="manifest_ledger_headers_schema_version_v1"),
    CheckConstraint("inventory_high_watermark >= 0", name="manifest_ledger_headers_high_watermark_nonnegative"),
    CheckConstraint("retained_row_count >= 0", name="manifest_ledger_headers_retained_row_count_nonnegative"),
    CheckConstraint("conflict_holder_count >= 0", name="manifest_ledger_headers_conflict_holder_count_nonnegative"),
    CheckConstraint("conflict_holder_count <= retained_row_count", name="manifest_ledger_headers_conflict_holder_count_bounded"),
    CheckConstraint("length(payload_sha256) = 64", name="manifest_ledger_headers_payload_digest_length"),
    CheckConstraint("length(manifest_sha256) = 64", name="manifest_ledger_headers_manifest_digest_length"),
    CheckConstraint("length(inventory_seal_ref) > 0", name="manifest_ledger_headers_seal_ref_non_empty"),
    CheckConstraint("bound_test_id IS NULL OR length(bound_test_id) > 0", name="manifest_ledger_headers_test_non_empty"),
)

manifest_ledger_rows = Table(
    "manifest_ledger_rows", uvm_metadata,
    Column("manifest_row_id", _ID, primary_key=True),
    Column("manifest_id", _ID, ForeignKey("manifest_ledger_headers.manifest_id"), nullable=False),
    Column("observation_id", _ID, nullable=False),
    Column("source_account_id", String, nullable=False),
    Column("run_id", String, nullable=False),
    Column("source_record_ordinal", Integer, nullable=False),
    Column("disposition_ordinal", Integer, nullable=False),
    Column("retained_evidence_sha256", String, nullable=False),
    Column("disposition", String, nullable=False),
    Column("resolution_id", _ID, ForeignKey("identity_resolutions.resolution_id"), nullable=True),
    Column("resolution_revision", Integer, nullable=True),
    Column("occurrence_id", _ID, ForeignKey("occurrences.occurrence_id"), nullable=True),
    Column("exclusion_rule_id", String, nullable=True),
    Column("exclusion_rule_version", Integer, nullable=True),
    Column("exclusion_evidence_ref", String, nullable=True),
    Column("exclusion_reason", String, nullable=True),
    Column("excluded_by_actor_id", String, nullable=True),
    Column("blocked_reason", String, nullable=True),
    ForeignKeyConstraint(
        ["observation_id", "source_account_id", "run_id", "source_record_ordinal"],
        ["source_observations.observation_id", "source_observations.source_account_id",
         "source_observations.run_id", "source_observations.source_record_ordinal"],
        name="fk_manifest_ledger_rows_retained_observation_position",
    ),
    UniqueConstraint("manifest_id", "observation_id", name="uq_manifest_ledger_rows_observation"),
    UniqueConstraint("manifest_id", "manifest_row_id", name="uq_manifest_ledger_rows_manifest_row"),
    CheckConstraint("source_record_ordinal >= 0", name="manifest_ledger_rows_ordinal_nonnegative"),
    CheckConstraint("disposition_ordinal >= 0", name="manifest_ledger_rows_disposition_ordinal_nonnegative"),
    CheckConstraint("length(retained_evidence_sha256) = 64", name="manifest_ledger_rows_evidence_digest_length"),
    CheckConstraint("disposition IN ('included', 'excluded_reviewed', 'blocked')", name="manifest_ledger_rows_disposition_known"),
    CheckConstraint("resolution_revision IS NULL OR resolution_revision > 0", name="manifest_ledger_rows_resolution_revision_positive"),
    CheckConstraint("exclusion_rule_version IS NULL OR exclusion_rule_version > 0", name="manifest_ledger_rows_exclusion_rule_version_positive"),
    CheckConstraint(
        "disposition <> 'included' OR (resolution_id IS NOT NULL AND resolution_revision IS NOT NULL AND occurrence_id IS NOT NULL)",
        name="manifest_ledger_rows_included_resolution_required",
    ),
    CheckConstraint(
        "disposition <> 'excluded_reviewed' OR (exclusion_rule_id IS NOT NULL AND exclusion_rule_version IS NOT NULL AND exclusion_evidence_ref IS NOT NULL AND exclusion_reason IS NOT NULL AND excluded_by_actor_id IS NOT NULL)",
        name="manifest_ledger_rows_reviewed_exclusion_required",
    ),
    CheckConstraint(
        "disposition <> 'blocked' OR (blocked_reason IS NOT NULL AND length(blocked_reason) > 0)",
        name="manifest_ledger_rows_blocked_reason_required",
    ),
    UniqueConstraint("manifest_id", "disposition_ordinal", name="uq_manifest_ledger_rows_disposition_ordinal"),
)

manifest_payload_records = Table(
    "manifest_payload_records", uvm_metadata,
    Column("payload_record_id", String, nullable=False),
    Column("manifest_id", _ID, ForeignKey("manifest_ledger_headers.manifest_id"), nullable=False),
    Column("payload_ordinal", Integer, nullable=False),
    Column("transformation_version", Integer, nullable=False),
    PrimaryKeyConstraint("manifest_id", "payload_record_id"),
    UniqueConstraint("manifest_id", "payload_ordinal", name="uq_manifest_payload_records_ordinal"),
    CheckConstraint("payload_ordinal >= 0", name="manifest_payload_records_ordinal_nonnegative"),
    CheckConstraint("length(payload_record_id) > 0", name="manifest_payload_records_id_non_empty"),
    CheckConstraint("transformation_version > 0", name="manifest_payload_records_transformation_positive"),
)

manifest_payload_memberships = Table(
    "manifest_payload_memberships", uvm_metadata,
    Column("manifest_id", _ID, nullable=False),
    Column("payload_record_id", String, nullable=False),
    Column("manifest_row_id", _ID, nullable=False),
    Column("membership_ordinal", Integer, nullable=False),
    ForeignKeyConstraint(
        ["manifest_id", "payload_record_id"],
        ["manifest_payload_records.manifest_id", "manifest_payload_records.payload_record_id"],
        name="fk_manifest_payload_memberships_payload_manifest",
    ),
    ForeignKeyConstraint(
        ["manifest_id", "manifest_row_id"],
        ["manifest_ledger_rows.manifest_id", "manifest_ledger_rows.manifest_row_id"],
        name="fk_manifest_payload_memberships_row_manifest",
    ),
    PrimaryKeyConstraint("manifest_id", "payload_record_id", "manifest_row_id"),
    UniqueConstraint("manifest_id", "payload_record_id", "membership_ordinal", name="uq_manifest_payload_memberships_ordinal"),
    CheckConstraint("membership_ordinal >= 0", name="manifest_payload_memberships_ordinal_nonnegative"),
)

ALL_MANIFEST_LEDGER_TABLES = (
    manifest_ledger_headers, manifest_ledger_rows, manifest_payload_records,
    manifest_payload_memberships,
)

ALL_ENGINE_OPERATION_TABLES = ALL_ENGINE_OPERATION_TABLES + ALL_MANIFEST_LEDGER_TABLES
ALL_ENGINE_OPERATION_TABLES = ALL_ENGINE_OPERATION_TABLES + (engine_occurrence_links,)


# G7-ING-01: immutable CLI request binding is reserved in the same
# transaction as the CE operation, before the external POST can be issued.
ce_import_request_bindings = Table(
    "ce_import_request_bindings", uvm_metadata,
    Column("operation_id", _ID, ForeignKey("engine_operation_requests.operation_id"), primary_key=True),
    Column("schema_version", Integer, nullable=False),
    Column("request_sha256", String(64), nullable=False),
    Column("canonical_request", String, nullable=False),
    Column("binding", JSON, nullable=False),
    Column("recorded_at", _TZ, nullable=False),
    CheckConstraint("schema_version = 1", name="ce_import_binding_version"),
    CheckConstraint("length(request_sha256) = 64", name="ce_import_binding_digest_length"),
)
ALL_ENGINE_OPERATION_TABLES = ALL_ENGINE_OPERATION_TABLES + (ce_import_request_bindings,)
