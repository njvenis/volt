"""UVM identity persistence metadata — SQLAlchemy Core slice (G1, version 1).

Core structural slice for the UVM identity records: group, workload,
incarnation, exposure and occurrence tables, plus the group↔CVE many-to-many
link. Separate UVM database: no DefectDojo tables (CR-01).

Semantics carried into DDL:

* Every record ID is a stable UVM UUID primary key. The DDL enforces
  uniqueness and referential integrity only; identity stability (an
  assigned UUID is never reassigned to a different record) is a
  writer/store contract (approved G1 Version 1 shared contracts), and
  this metadata claims no row-level immutability.
* ``groups`` carries the full namespaced native key —
  ``(source_family, native_id_scheme, native_id_authority,
  native_id_value)`` — as one UNIQUE constraint (CR-02). ``group_cve_refs``
  is a many-to-many reference: a CVE shared by several groups is never a
  group-merge basis, because the unique key lives on the native columns only.
* ``revision`` is a positive integer on every record.
* Scanner observation timestamps (``first_observed_at``) are nullable:
  ``NULL`` means unknown; it is never the collection time.
* ``incarnations``, ``exposures`` and ``occurrences`` carry their foreign-key
  references plus the same uniqueness the in-memory identity indexes enforce
  (per-workload locator, per (group, workload) exposure, per
  (exposure, incarnation, component) occurrence — CR-03/CR-04).
* ``occurrences`` additionally carries the V2 birth anchor
  (``birth_exposure_id`` / ``birth_exposure_revision``, FR-ID-01/02, CR-03
  amendment): nullable, co-present, positive revision, stable-exposure FK;
  head metadata ahead of the additive ``0003`` migration.

Column names match the committed identity DTO fields in
``uvm/identity/model.py``. This module only defines metadata; it does not
create an engine or database.

Explicit conversion boundaries for the remaining review defects:

* Record IDs are committed canonical UUID *strings* (``new_id()``), so the
  schema type is ``Uuid(as_uuid=False)``: strings bind and round-trip
  unchanged on every dialect; no ``uuid.UUID`` conversion happens at the
  store boundary (CR-02/03/04 records are addressed by their stable string
  IDs).
* An occurrence's exposure and incarnation must belong to the *same*
  workload. The redundant ``occurrences.workload_id`` plus composite
  foreign keys onto ``exposures(exposure_id, workload_id)`` and
  ``incarnations(incarnation_id, workload_id)`` enforce that at the DDL
  level, not only in the future writer (CR-03).
* Uniqueness over the nullable ``host_locator`` / ``component_locator``
  is the ordinary scoped UNIQUE constraint. A withdrawn or unverified
  locator may be ``NULL``, and ``NULL`` is never a matching key: several
  retained records in the same scope may carry unknown locators and keep
  their distinct UUID identities (Proposed V1 locator-correction
  clarification; CR-03/CR-04). Only known, non-null locators participate
  in scoped uniqueness, on both PostgreSQL and SQLite.
"""

from __future__ import annotations

import copy

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    JSON,
    MetaData,
    String,
    Table,
    Uuid,
    UniqueConstraint,
    false,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles

# Dialect-specific deferral rendering for the current-membership
# occurrence FK: the current head metadata and the migrations must agree
# per dialect (docs/g1-membership-correction-schema-amendment.md).
# Migration 0002 re-emits the FK ``DEFERRABLE INITIALLY IMMEDIATE`` on
# PostgreSQL, so head metadata renders that exact form on PostgreSQL.
# Frozen 0001 created it without the deferral keyword on SQLite and 0002
# emits no SQLite DDL for it, so head metadata renders the immediate
# form there: the correction writer defers it at runtime via the
# correction-transaction ``PRAGMA defer_foreign_keys=ON`` (writer route,
# no DDL difference), so the SQLite ``create_all`` head and the migrated
# head carry identical occurrences DDL.
class _DeferrableOnPostgresFK(ForeignKeyConstraint):
    """The current-membership occurrence FK; the deferral keywords
    render on PostgreSQL only (see the module note above)."""


@compiles(_DeferrableOnPostgresFK)
def _render_deferrable_on_postgres(element, compiler, **kw):
    """Standard FK rendering, with the deferral clause applied to a
    one-off copy of the constraint for PostgreSQL compilations only
    (the shared metadata object is left dialect-neutral)."""
    if compiler.dialect.name != "postgresql":
        return compiler.visit_foreign_key_constraint(element)
    # Render from a one-off copy: the shared metadata object is never
    # mutated, so a concurrent SQLite compilation of the same metadata
    # can never observe a transient deferral flag (no global mutable
    # metadata toggles).
    pg_fk = copy.copy(element)
    pg_fk.deferrable, pg_fk.initially = True, "IMMEDIATE"
    return compiler.visit_foreign_key_constraint(pg_fk)


# UTC stored timestamps, explicit display timezone later (project convention).
_TZ = DateTime(timezone=True)
# Canonical string IDs (new_id()); as_uuid=False so strings bind/round-trip
# unchanged. Renders as native UUID on PostgreSQL, CHAR(36) elsewhere.
_ID = Uuid(as_uuid=False)

uvm_metadata = MetaData(
    naming_convention={
        "pk": "pk_%(table_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ix": "ix_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s",
    }
)

groups = Table(
    "groups",
    uvm_metadata,
    Column("group_id", _ID, primary_key=True),
    Column("source_family", String, nullable=False),
    Column("native_id_scheme", String, nullable=False),
    Column("native_id_authority", String, nullable=False),
    Column("native_id_value", String, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("created_at", _TZ, nullable=False),
    # The complete namespace is the identity; no shorter prefix is.
    UniqueConstraint(
        "source_family", "native_id_scheme", "native_id_authority",
        "native_id_value",
        name="uq_groups_native_key",
    ),
    CheckConstraint("revision > 0", name="groups_revision_positive"),
)

group_cve_refs = Table(
    "group_cve_refs",
    uvm_metadata,
    Column("group_id", _ID, ForeignKey("groups.group_id"), primary_key=True),
    # External reference string (e.g. "CVE-2024-12345"); not a UVM record.
    Column("cve_ref", String, nullable=False, primary_key=True),
    Index("ix_group_cve_refs_cve_ref", "cve_ref"),
)

workloads = Table(
    "workloads",
    uvm_metadata,
    Column("workload_id", _ID, primary_key=True),
    # JSONB on PostgreSQL, JSON elsewhere.
    Column("stable_attrs", JSONB().with_variant(JSON, "sqlite"),
           nullable=False),
    Column("revision", Integer, nullable=False),
    Column("created_at", _TZ, nullable=False),
    CheckConstraint("revision > 0", name="workloads_revision_positive"),
)

incarnations = Table(
    "incarnations",
    uvm_metadata,
    Column("incarnation_id", _ID, primary_key=True),
    Column("workload_id", _ID, ForeignKey("workloads.workload_id"),
           nullable=False),
    Column("host_locator", String, nullable=True),
    Column("image_ref", String, nullable=True),
    # None means unknown; never the collection time.
    Column("first_observed_at", _TZ, nullable=True),
    Column("revision", Integer, nullable=False),
    Column("created_at", _TZ, nullable=False),
    # A known, non-null locator identifies at most one incarnation per
    # workload. NULL is never a matching key: several retained
    # incarnations in one workload may have unknown locators (corrected
    # to unknown without changing their UUIDs) and remain distinct rows.
    UniqueConstraint("workload_id", "host_locator",
                     name="uq_incarnations_workload_locator"),
    # Parent pair for the composite occurrence FK (see occurrences).
    UniqueConstraint("incarnation_id", "workload_id",
                     name="uq_incarnations_id_workload"),
    CheckConstraint("revision > 0", name="incarnations_revision_positive"),
)

exposures = Table(
    "exposures",
    uvm_metadata,
    Column("exposure_id", _ID, primary_key=True),
    Column("group_id", _ID, ForeignKey("groups.group_id"), nullable=False),
    Column("workload_id", _ID, ForeignKey("workloads.workload_id"),
           nullable=False),
    # Earliest supported detection; retained on succession, never reset.
    Column("first_observed_at", _TZ, nullable=True),
    Column("revision", Integer, nullable=False),
    Column("created_at", _TZ, nullable=False),
    # One exposure per (group, workload); stable across verified rebuilds.
    UniqueConstraint("group_id", "workload_id",
                     name="uq_exposures_group_workload"),
    # Parent pair for the composite occurrence FK; also satisfies the PG
    # requirement for a unique index on the referenced columns.
    UniqueConstraint("exposure_id", "workload_id",
                     name="uq_exposures_id_workload"),
    CheckConstraint("revision > 0", name="exposures_revision_positive"),
)

occurrences = Table(
    "occurrences",
    uvm_metadata,
    Column("occurrence_id", _ID, primary_key=True),
    # No single-column FKs: the composite FKs below are the reference
    # rule (they also require the exposure/incarnation parents to exist).
    Column("exposure_id", _ID, nullable=False),
    Column("incarnation_id", _ID, nullable=False),
    # Redundant workload: the composite FKs below pin the occurrence to
    # ONE workload, so exposure(workload A) + incarnation(workload B)
    # is rejected at the DDL level (CR-03), not only by the writer.
    Column("workload_id", _ID, nullable=False),
    Column("component_locator", String, nullable=True),
    # 0004 birth-locator amendment (FR-ID-01/02, CR-03): a creation
    # transaction records even a NULL locator explicitly.  False/NULL is
    # the legacy absence marker; True/NULL means unknown at birth.
    Column("birth_component_locator", String, nullable=True),
    Column("birth_component_locator_recorded", Boolean,
           nullable=False, server_default=false()),
    # G1 V2 revision-anchor amendment (FR-ID-01/02, CR-03; approved at
    # d5fe24d): the exposure the occurrence was created INTO. Captured from
    # the locked exposure row in the creating transaction (writer route;
    # this slice carries metadata only). References the STABLE exposure
    # ID — the same rule as exposure_workload_memberships — so a later
    # correction moving the occurrence's exposure does not invalidate the
    # birth anchor. Both fields are co-present or both NULL (portable
    # CHECK below); the revision is the exposure's revision at creation,
    # a positive integer, and is never a free-running counter.
    Column("birth_exposure_id", _ID,
           ForeignKey("exposures.exposure_id"), nullable=True),
    Column("birth_exposure_revision", Integer, nullable=True),
    # None means unknown observation time; never the collection time.
    Column("first_observed_at", _TZ, nullable=True),
    Column("first_ingested_at", _TZ, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("created_at", _TZ, nullable=False),
    # DEFERRABLE INITIALLY IMMEDIATE from 0002 onward on PostgreSQL: a
    # guarded correction transaction defers ONLY this current-membership
    # FK for its transient exposure move (G1 correction amendment);
    # otherwise it stays immediate. Frozen 0001 created it immediate;
    # migration 0002 applies the PostgreSQL ALTER and the downgrade
    # restores the immediate form. SQLite renders the immediate form so
    # the head metadata matches the migrated DDL (the writer defers via
    # the correction-transaction PRAGMA defer_foreign_keys=ON; no DDL
    # difference).
    _DeferrableOnPostgresFK(
        ["exposure_id", "workload_id"],
        ["exposures.exposure_id", "exposures.workload_id"],
        name="fk_occurrences_exposure_id_workload_id_exposures",
    ),
    ForeignKeyConstraint(
        ["incarnation_id", "workload_id"],
        ["incarnations.incarnation_id", "incarnations.workload_id"],
        name="fk_occurrences_incarnation_id_workload_id_incarnations",
    ),
    # A known, non-null component_locator admits at most one occurrence
    # per (exposure, incarnation). NULL is never a matching key: several
    # retained occurrences in the same scope may have unknown components
    # (corrected to unknown without changing their UUIDs) and remain
    # distinct rows (CR-04), identically on PostgreSQL and SQLite.
    UniqueConstraint("exposure_id", "incarnation_id", "component_locator",
                     name="uq_occurrences_exposure_incarnation_component"),
    CheckConstraint("revision > 0", name="occurrences_revision_positive"),
    CheckConstraint(
        "birth_component_locator_recorded IN (0, 1) AND "
        "((birth_component_locator_recorded = 0 "
        "AND birth_component_locator IS NULL) OR "
        "birth_component_locator_recorded = 1)",
        name="occurrences_birth_component_locator_consistent",
        _create_rule=lambda compiler: compiler.dialect.name == "sqlite",
    ),
    CheckConstraint(
        "birth_component_locator_recorded IN (FALSE, TRUE) AND "
        "((birth_component_locator_recorded = FALSE "
        "AND birth_component_locator IS NULL) OR "
        "birth_component_locator_recorded = TRUE)",
        name="occurrences_birth_component_locator_consistent",
        _create_rule=lambda compiler: compiler.dialect.name == "postgresql",
    ),
    # Birth anchor coherence (V2 amendment): no partial anchors — both
    # are NULL (legacy pre-V2 row) or both present with a positive
    # revision. The FK grounds the stable exposure ID itself.
    CheckConstraint(
        "(birth_exposure_id IS NULL AND birth_exposure_revision IS NULL) "
        "OR (birth_exposure_id IS NOT NULL "
        "AND birth_exposure_revision IS NOT NULL "
        "AND birth_exposure_revision > 0)",
        name="occurrences_birth_anchor_consistent",
    ),
)

# G1 populated-exposure correction amendment (FR-ID-02/CR-03): the
# historical exposure/workload pair key. Membership rows are retained
# when a correction moves an exposure, so the foreign keys reference the
# STABLE exposure and workload IDs — never the exposure's current
# (exposure_id, workload_id) pair — and an old pair stays valid after the
# move. Head metadata only until migration 0002 lands: the frozen 0001
# table set (ALL_TABLES, asserted by tests/persistence/test_migration.py)
# is unchanged, so ``uvm_metadata.create_all`` head differs from migration
# 0001 by exactly this table.
exposure_workload_memberships = Table(
    "exposure_workload_memberships",
    uvm_metadata,
    Column("exposure_id", _ID, ForeignKey("exposures.exposure_id"),
           primary_key=True),
    Column("workload_id", _ID, ForeignKey("workloads.workload_id"),
           primary_key=True),
)

ALL_TABLES = (groups, group_cve_refs, workloads, incarnations, exposures,
              occurrences)
