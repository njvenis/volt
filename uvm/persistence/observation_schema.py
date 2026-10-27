"""UVM source-observation/provenance persistence slice (G1, version 1).

Additive slice for the retained source observations (``SourceObservationV1``)
and the ``QuarantinedIdReuse`` records, in the separate UVM database. It
registers its tables on the same ``uvm_metadata`` as ``schema.py``; it does
not define its own metadata, engine, writer or migration.

Semantics carried into DDL:

* ``observation_id`` is a canonical UVM UUID string primary key
  (``Uuid(as_uuid=False)``, like ``schema.py``). Every retained row keeps a
  unique identity: the first holder keeps a reused ID and a later conflicting
  holder is retained under its distinct surrogate ID, so the primary key
  never forces two retained rows to share an identity.
* ``observed_at`` (scanner observation time) and ``collected_at`` (collection
  time) are distinct columns; ``collected_at`` is required and ``observed_at``
  is nullable — an unknown observation time is stored as ``NULL`` and is never
  filled with the collection time (FR-ID / G1 envelope; never inferred).
* ``missing_fields`` is an explicit JSON list of ``{field, reason}`` objects:
  a null optional field must be declared here. The DDL claim is
  ``NOT NULL`` only — a SQL-NULL declaration list is rejected. Per-field JSON
  shape (a list of ``{field, reason}`` objects whose reason is one of
  ``not_supplied`` / ``not_applicable`` / ``unverified``) is a writer/DTO
  claim (``SourceObservationV1`` / ``MissingField``), not a SQL claim: no
  portable single-dialect CHECK expresses it, and this module does not
  claim SQL proves it.
* Raw evidence is stored as ``raw_evidence_ref`` + ``raw_evidence_sha256``
  (reference and digest), never the raw bytes. The DDL claim is digest
  *length* 64 only; hex-ness of the 64 characters is a writer-level claim
  (no portable regex CHECK exists between SQLite and PostgreSQL).
* ``vulnerability_refs`` is the one optional JSON column; a Python
  ``None`` binds true SQL ``NULL`` (not the JSON document ``null``), so a
  missing reference set reads back as a true unknown to external SQL
  consumers (CR-03: ``jsonb_typeof`` never reports ``null`` for a missing
  value and ``IS NULL`` is true). A non-``None`` reference list still
  serialises as a JSON array, exactly as plain JSON/JSONB.
* Persisted store state (CR-03/04, deterministic ``ObservationStore``
  restoration): ``retention_order`` is the unique sequence slot in which the
  row was retained, and ``ingest_outcome`` records whether the row was
  retained as ``created`` or ``conflict``. Together with the (non-unique)
  position index these make a same-position changed-row replay distinguishable
  in the persisted state: which holder is the created row, which is the
  conflict, and in what order. They record the store state; they do NOT prove
  causal history (an impossible outcome order passes the DDL) — validating
  the guarded writer/restoration causal order is a pending writer-level check
  (unit evidence only, integration-unverified). Only ``created`` /
  ``conflict`` are known outcomes — a ``duplicate`` retry retains no new row.
* ``occurrence_id`` is a nullable foreign key onto
  ``occurrences.occurrence_id``: null while the observation is unresolved,
  exactly one occurrence after safe resolution.
* The composite unique constraint over
  ``(observation_id, source_account_id, run_id, source_record_ordinal)`` adds
  no restriction beyond the ``observation_id`` primary key (a leading unique
  column makes it redundant as a cardinality claim); it exists only as the
  portable composite-foreign-key target that binds a quarantine holder's
  position to its retained observation row (below).
* No uniqueness constraint over the source position
  ``(source_account_id, run_id, source_record_ordinal)`` or over
  ``(position, raw_evidence_sha256)``: conflicting bytes or a changed parsed
  row at the same position are both retained as distinct rows, never silently
  deduplicated (CR-04, G1 conflict-retention contract).

``quarantined_id_reuse`` persists one record per attempted (reused)
``observation_id`` (its primary key). Its holders are normalised rows in
``quarantined_id_reuse_holders``: one row per holder carrying the source
position and the identity the holder is retained under. The holder's
position is bound to its retained observation row by a composite foreign key
``(retained_id, source_account_id, run_id, source_record_ordinal)`` onto
``source_observations (observation_id, source_account_id, run_id,
source_record_ordinal)`` — so a holder at a wrong account/run/ordinal cannot
point at a genuine retained row by ID alone, and first holder and surrogates
round-trip to retained observation rows, not an unchecked JSON reference.
DDL-enforced per-record invariants: unique (attempted_id, holder_ordinal),
unique (attempted_id, retained_id), non-negative ordinals, the first holder
(ordinal 0) keeps the attempted ID, and the composite position FK. Two
holders may sit at the same position (a changed parsed row or different
bytes at the same account/run/ordinal, CR-04). Writer-level (not
DDL-expressible): at least two holders per record and dense 0..n-1 ordinals.
The DDL makes no cross-record uniqueness claim: cross-quarantine reuse of the
same retained row (a retained row appearing as a holder under two different
records) can be legitimate.

This module only defines metadata; it does not create a writer/store, a
write guard, or a database, and it claims no row-level immutability: the DDL
enforces uniqueness and referential integrity only; never reassigning an ID
is a writer/store contract.
"""

from __future__ import annotations

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    JSON,
    PrimaryKeyConstraint,
    String,
    Table,
    TypeDecorator,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import CompileError

from uvm.persistence.schema import uvm_metadata

_TZ = DateTime(timezone=True)
_ID = Uuid(as_uuid=False)
# JSONB on PostgreSQL, JSON elsewhere (same convention as schema.py).
_JSON = JSONB().with_variant(JSON, "sqlite")


class _NoneAsSqlNull(TypeDecorator):
    """Optional JSON: binds a Python ``None`` as true SQL ``NULL`` instead
    of the JSON document ``null``. SQLAlchemy's JSON/JSONB bind/literal
    processors serialise every value (``json.dumps(None)`` == ``'null'``),
    which on PostgreSQL stores a JSONB ``null`` document (``jsonb_typeof``
    = ``'null'``, ``IS NULL`` false) — not the true unknown an external
    SQL consumer expects for a missing optional (CR-03). Non-``None``
    values go through the inner JSON/JSONB processor unchanged.

    A TypeDecorator (rather than a JSON subclass) is required: the dialect
    type-substitution (``adapt_type``) copies a JSON subclass's constructor
    arguments into the dialect's own JSON implementation, dropping any
    overridden processors, whereas a TypeDecorator has no matching
    colspec and keeps its own.

    Literal compilation mirrors the bind path: a ``None`` literal renders
    the SQL ``NULL`` literal, and a non-``None`` value defers to the inner
    JSON/JSONB literal processor. Because the inner type has no literal
    renderer on the supported dialects (SQLite JSON, PostgreSQL JSONB), a
    non-``None`` literal raises the normal ``CompileError`` rather than
    leaking a raw Python value into the compiler (Reviewer 01dce98c
    edge); this is the same error plain JSON/JSONB raises for
    ``literal_binds`` and does not affect the bound-parameter path, which
    is the normal write path.
    """

    impl = JSONB().with_variant(JSON, "sqlite")
    cache_ok = True

    def bind_processor(self, dialect):
        inner = self.impl_instance.bind_processor(dialect)

        def process(value):
            if value is None:
                return None
            return value if inner is None else inner(value)

        return process

    def literal_processor(self, dialect):
        inner = self.impl_instance.literal_processor(dialect)

        def process(value):
            if value is None:
                return "NULL"
            if inner is None:
                # Never leak the raw Python value to the compiler: raise
                # the same normal CompileError SQLAlchemy raises for a
                # non-literalisable bind value of this datatype.
                raise CompileError(
                    f"No literal value renderer is available for literal "
                    f"value {value!r} with datatype "
                    f"{self.impl_instance.__class__.__name__}")
            return inner(value)

        return process


# Optional JSON: same JSONB/JSON convention as _JSON, but Python None
# binds SQL NULL (see _NoneAsSqlNull).
_NULLABLE_JSON = _NoneAsSqlNull()

source_observations = Table(
    "source_observations",
    uvm_metadata,
    Column("schema_version", Integer, nullable=False),
    Column("observation_id", _ID, primary_key=True),
    Column("revision", Integer, nullable=False),
    Column("source_family", String, nullable=False),
    Column("source_account_id", String, nullable=False),
    Column("run_id", String, nullable=False),
    Column("source_record_ordinal", Integer, nullable=False),
    Column("collection_status", String, nullable=False),
    # Collection time: required, never the scanner observation time.
    Column("collected_at", _TZ, nullable=False),
    Column("raw_evidence_ref", String, nullable=False),
    # DDL claim: length 64 only (hex-ness is a writer-level claim).
    Column("raw_evidence_sha256", String, nullable=False),
    # Explicit {field, reason} declarations for null optional fields.
    # DDL claim: NOT NULL only; per-field JSON shape is a writer claim.
    Column("missing_fields", _JSON, nullable=False),
    # Optional fields: NULL only when declared in missing_fields.
    Column("observed_at", _TZ, nullable=True),
    Column("native_id_scheme", String, nullable=True),
    Column("native_id_authority", String, nullable=True),
    Column("native_id_value", String, nullable=True),
    Column("asset_locator", String, nullable=True),
    Column("component_locator", String, nullable=True),
    Column("source_record_locator", String, nullable=True),
    Column("source_rating", String, nullable=True),
    # Optional JSON; None binds true SQL NULL, not the JSON document
    # 'null' (CR-03 true unknown; see _NULLABLE_JSON).
    Column("vulnerability_refs", _NULLABLE_JSON, nullable=True),
    Column("source_first_seen_at", _TZ, nullable=True),
    Column("report_id", String, nullable=True),
    Column("coverage_scope", String, nullable=True),
    # Null until safe resolution; then exactly one UVM occurrence.
    Column("occurrence_id", _ID,
           ForeignKey("occurrences.occurrence_id"), nullable=True),
    # Persisted store state: the unique retention sequence slot and the
    # created/conflict outcome under which the row was retained, so a
    # same-position changed-row replay stays distinguishable and the
    # store state is restorable.
    Column("retention_order", Integer, nullable=False),
    Column("ingest_outcome", String, nullable=False),
    # Conflict retention (CR-04): NO unique constraint over the source
    # position or (position, digest) — conflicting bytes and changed parsed
    # rows at the same position stay as distinct retained rows.
    Index(
        "ix_source_observations_source_position",
        "source_account_id", "run_id", "source_record_ordinal",
    ),
    UniqueConstraint("retention_order",
                     name="uq_source_observations_retention_order"),
    # Redundant with the observation_id primary key (a leading unique column
    # makes it add no restriction); it exists only as the composite-FK
    # target that binds a quarantine holder's position to its retained row.
    UniqueConstraint("observation_id", "source_account_id", "run_id",
                     "source_record_ordinal",
                     name="uq_source_observations_retained_position"),
    CheckConstraint("schema_version = 1",
                    name="source_observations_schema_version_v1"),
    CheckConstraint("revision > 0",
                    name="source_observations_revision_positive"),
    CheckConstraint(
        "collection_status IN ('success', 'partial', 'failed')",
        name="source_observations_collection_status_known",
    ),
    CheckConstraint(
        "ingest_outcome IN ('created', 'conflict')",
        name="source_observations_ingest_outcome_known",
    ),
    CheckConstraint("retention_order >= 0",
                    name="source_observations_retention_order_nonnegative"),
    CheckConstraint("length(raw_evidence_sha256) = 64",
                    name="source_observations_raw_digest_length"),
)

quarantined_id_reuse = Table(
    "quarantined_id_reuse",
    uvm_metadata,
    # One durable record per attempted (reused) observation_id.
    Column("attempted_id", _ID, primary_key=True),
    Column("reason", String, nullable=False),
)

quarantined_id_reuse_holders = Table(
    "quarantined_id_reuse_holders",
    uvm_metadata,
    # One row per holder, in retention order (first holder first).
    Column("attempted_id", _ID,
           ForeignKey("quarantined_id_reuse.attempted_id"), nullable=False),
    Column("holder_ordinal", Integer, nullable=False),
    # The holder's source position.
    Column("source_account_id", String, nullable=False),
    Column("run_id", String, nullable=False),
    Column("source_record_ordinal", Integer, nullable=False),
    # The identity the holder is retained under: the first holder keeps the
    # attempted ID, later holders carry distinct surrogate UUIDs. The
    # composite FK below (with the holder's position columns) references a
    # retained source_observations row, so first holder and surrogates
    # round-trip to retained rows and a wrong-position holder cannot point
    # at a genuine retained row by ID alone.
    Column("retained_id", _ID, nullable=False),
    PrimaryKeyConstraint("attempted_id", "holder_ordinal"),
    UniqueConstraint("attempted_id", "retained_id",
                     name="uq_quarantined_id_reuse_holders_retained"),
    # The holder's source position is bound to its retained observation row:
    # a composite FK onto (observation_id, account, run, ordinal). No
    # per-record position uniqueness: two holders may sit at the same
    # position (CR-04 conflict retention).
    ForeignKeyConstraint(
        ["retained_id", "source_account_id", "run_id",
         "source_record_ordinal"],
        ["source_observations.observation_id",
         "source_observations.source_account_id",
         "source_observations.run_id",
         "source_observations.source_record_ordinal"],
        name="fk_quarantined_id_reuse_holders_retained_position"),
    CheckConstraint("holder_ordinal >= 0",
                    name="quarantined_id_reuse_holders_ordinal_nonnegative"),
    # The first holder (ordinal 0) keeps the attempted (reused) ID; only
    # later holders may carry a distinct retained identity.
    CheckConstraint(
        "holder_ordinal > 0 OR retained_id = attempted_id",
        name="quarantined_id_reuse_holders_first_keeps_attempted_id",
    ),
)

ALL_OBSERVATION_TABLES = (source_observations, quarantined_id_reuse,
                          quarantined_id_reuse_holders)
