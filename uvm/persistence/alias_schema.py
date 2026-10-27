"""UVM durable alias/history metadata persistence slice (G1, version 1).

Additive, metadata-only slice for the durable counterpart of the in-memory
``IdentityState`` alias maps from ``uvm/identity/model.py`` (Scout finding:
``aliases`` / ``mapping_aliases`` / ``group_key_aliases`` have no durable
form). It registers two alias event tables on the shared
``uvm_metadata`` (importing ``lineage_schema`` so ``correction_records`` is
registered for the ``correction_id`` foreign key):

* ``group_key_alias_events`` — a former 4-part
  ``(source_family, native_id_scheme, native_id_authority,
  native_id_value)`` native group key retained as a historical alias of the
  stable group UUID it once named (in-memory ``group_key_aliases``).
* ``mapping_alias_events`` — scoped historical mapping aliases for
  workload / incarnation / exposure / occurrence corrections
  (in-memory ``mapping_aliases``).

Events are metadata-only appends at the WRITER level: every row carries
its own canonical UUID string primary key, the ``correction_id`` that
caused the alias state change, the ``action`` (``activate`` = the
correction made the value historical for the target record; ``retire`` =
a later correction restored the value to active, so the alias entry is
retired), the durable event order (``event_sequence``, a positive integer
total order), the event time (``occurred_at``), the target stable record
ID the alias resolves to, and the provenance/evidence reference. A retire
is an additional retained row at the writer level — this slice defines no
UPDATE/DELETE path and claims no DDL-level row immutability: direct SQL
UPDATE/DELETE remains possible until a writer/role/trigger guard exists,
and both activations and retires for the same key are writer-retained
over time.

Durable ordering (G1 review correction for FR-ID-02):

* ``occurred_at`` alone does not order a key's events: an activate and a
  retire can carry equal timestamps. ``event_sequence`` is the durable
  total order — the projection of the latest event per key orders by
  ``event_sequence`` (with ``occurred_at`` as the display/audit time).
* The DDL enforces only ``event_sequence > 0`` and per-table uniqueness;
  it does NOT claim to enforce causal or per-key monotonicity. A future
  guarded writer assigns monotonically increasing sequence values
  transactionally (e.g. the table's next value taken and committed
  inside the same transaction as the event insert).
* The ``correction_id`` foreign key establishes only that the referenced
  correction row EXISTS. It does not establish that the correction's
  target record, field, or old value corresponds to the alias event; a
  future writer must validate that correspondence.

Scope and namespace distinctions carried into DDL (CR-03/CR-04, FR-ID-02):

* A group key alias is meaningful only within its complete 4-part native
  namespace (all four columns NOT NULL); no shorter prefix is a key
  (CR-02).
* A mapping alias key is ``record_type`` + ``field_name`` + its scope
  elements + the former value:
  * workload corrections: no scope element (3-part in-memory key);
  * incarnation host-locator corrections: scoped to the owning workload
    (``scope_a``) — the same host locator under an unrelated workload is
    not blocked and coexists as a distinct row;
  * exposure mapping corrections: scoped to the untouched counterpart
    (``scope_a`` = the group for a workload mapping, the workload for a
    group mapping);
  * occurrence component-locator corrections: scoped to the
    (exposure, incarnation) pair (``scope_a`` = exposure, ``scope_b`` =
    incarnation) — the same component name under another incarnation is
    not blocked;
  * occurrence parent-mapping corrections (former exposure/incarnation):
    per-record scope (``scope_a`` = the occurrence record ID).
  ``scope_b`` may only be present together with ``scope_a`` (portable
  CHECK), mirroring the in-memory key shapes (3-, 4- and 5-part tuples).

Writer-projection boundary (documented, not claimed by DDL):

* This slice ships NO uniqueness over the alias key (native parts, or
  ``record_type`` / ``field_name`` / ``scope_a`` / ``scope_b`` /
  ``old_value``). "Uniqueness of the currently ACTIVE aliases" is a
  WRITER PROJECTION over the event log (the latest event per key, by the
  durable ``event_sequence`` total order, wins): a key legitimately
  carries several retained events over its lifetime, so an event-log DDL
  cannot and does not claim active-alias uniqueness. The lookup indexes
  are deliberately non-unique. The DDL also claims no row immutability:
  no trigger, role or writer guard exists yet, so direct SQL UPDATE and
  DELETE are possible; "append-only" is writer behaviour, not a DDL
  property.
* ``target_record_id`` has no foreign key: ``record_type`` selects which
  core table (workload, incarnation, exposure or occurrence) the ID
  belongs to, exactly as ``correction_records.record_id`` is unbound
  (same convention; the writer/store binds it).
* ``scope_a`` / ``scope_b`` are unbound UUID columns: their meaning
  (workload / group / exposure / incarnation / occurrence ID) depends on
  ``record_type`` + ``field_name``; a portable FK cannot select the target
  table. ``target_group_id`` IS bound to ``groups.group_id`` because the
  core table there is fixed.
* ``record_type`` carries no closed value policy (the committed
  ``CorrectionRecord`` DTO has none; the engine validates the target
  bucket) — only ``action`` is a closed vocabulary (``activate`` /
  ``retire``).
* The in-memory flat ``aliases`` map (former value -> record ID,
  first-wins) is a STORE PROJECTION of the mapping-alias events (its
  values are the ``old_value`` last elements) and is not a third table;
  nothing here changes the ``CorrectionRecord`` DTO.

This module only defines metadata; it does not create an engine, writer,
store, migration or database, and it claims no row-level immutability.
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    String,
    Table,
    UniqueConstraint,
    Uuid,
)

from uvm.persistence.lineage_schema import correction_records  # noqa: F401
from uvm.persistence.engine_operation_schema import (  # noqa: F401
    ALL_ENGINE_OPERATION_TABLES,
)
from uvm.persistence.schema import groups, uvm_metadata

# UTC stored timestamps, explicit display timezone later (project convention).
_TZ = DateTime(timezone=True)
# Canonical string IDs (new_id()); as_uuid=False so strings bind/round-trip
# unchanged (same convention as schema.py).
_ID = Uuid(as_uuid=False)

# Closed event vocabulary (FR-ID-02 alias state changes): the correction
# made a value historical (activate) or restored it to active (retire).
_ALIAS_ACTIONS = "action IN ('activate', 'retire')"

group_key_alias_events = Table(
    "group_key_alias_events",
    uvm_metadata,
    Column("alias_event_id", _ID, primary_key=True),
    # The correction whose old native key this event records. FK onto the
    # retained correction row: it establishes the correction EXISTS, not
    # that its target/field/old value correspond (the future writer
    # validates that).
    Column("correction_id", _ID,
           ForeignKey("correction_records.correction_id"), nullable=False),
    Column("action", String, nullable=False),
    # The complete 4-part former native key; a key is meaningful only
    # within its full namespace (CR-02) — every part required.
    Column("source_family", String, nullable=False),
    Column("native_id_scheme", String, nullable=False),
    Column("native_id_authority", String, nullable=False),
    Column("native_id_value", String, nullable=False),
    # The stable group UUID the former key resolves to. Bound: the core
    # table for a group alias is always ``groups``.
    Column("target_group_id", _ID, ForeignKey("groups.group_id"),
           nullable=False),
    # Provenance/evidence reference for the correction (audited; never
    # an empty string).
    Column("evidence_ref", String, nullable=False),
    # Event time (UTC): display/audit time. NOT the durable order — equal
    # timestamps do not order the history (see event_sequence).
    Column("occurred_at", _TZ, nullable=False),
    # Durable total order over this table's events (FR-ID-02 projection
    # order): positive and unique within the table ONLY. The DDL does not
    # enforce causal or per-key monotonicity; a future guarded writer
    # assigns monotonically increasing values transactionally. Ordering
    # of equal-timestamp activate/retire pairs recovers from this column
    # alone.
    Column("event_sequence", BigInteger, nullable=False),
    CheckConstraint("event_sequence > 0",
                    name="group_key_alias_events_event_sequence_positive"),
    # Per-event uniqueness only (the sequence and the PK); no alias-key
    # uniqueness (writer-projection boundary above).
    UniqueConstraint("event_sequence",
                     name="group_key_alias_events_event_sequence_unique"),
    # Event-log history over the alias key: the 4-part key carries a
    # NON-UNIQUE lookup index only (writer-projection boundary above).
    Index("ix_group_key_alias_events_native_key",
          "source_family", "native_id_scheme", "native_id_authority",
          "native_id_value"),
    Index("ix_group_key_alias_events_correction_time",
          "correction_id", "occurred_at"),
    CheckConstraint(_ALIAS_ACTIONS,
                    name="group_key_alias_events_action_known"),
    # Provenance is required audited evidence, never an empty string.
    CheckConstraint("length(evidence_ref) > 0",
                    name="group_key_alias_events_evidence_ref_non_empty"),
)

mapping_alias_events = Table(
    "mapping_alias_events",
    uvm_metadata,
    Column("alias_event_id", _ID, primary_key=True),
    # FK establishes the correction EXISTS only (no correspondence claim
    # — the future writer validates target/field/old value).
    Column("correction_id", _ID,
           ForeignKey("correction_records.correction_id"), nullable=False),
    Column("action", String, nullable=False),
    # Which record type the corrected mapping belongs to (workload,
    # incarnation, exposure or occurrence); no closed value policy
    # (committed DTO convention — the engine validates the bucket).
    Column("record_type", String, nullable=False),
    # Which field/value the correction replaced (e.g. host_locator,
    # component_locator, exposure_id, incarnation_id or a stable workload
    # field).
    Column("field_name", String, nullable=False),
    # Scope elements of the in-memory alias key (see module docstring):
    # scope_a = owning workload / untouched counterpart / exposure /
    # occurrence record ID; scope_b = incarnation (occurrence
    # component-locator scope). Unbound UUIDs (target table depends on
    # record_type + field_name). NULL for the unscoped workload shape.
    Column("scope_a", _ID, nullable=True),
    Column("scope_b", _ID, nullable=True),
    # The former (now historical) value. Aliases only exist for a known
    # former value (the in-memory maps never carry a NULL old value).
    Column("old_value", String, nullable=False),
    # The stable record UUID the alias resolves to. Unbound: record_type
    # selects the target core table (same convention as
    # correction_records.record_id — writer/store binds it).
    Column("target_record_id", _ID, nullable=False),
    Column("evidence_ref", String, nullable=False),
    # Event time (UTC): display/audit time (NOT the durable order — see
    # event_sequence).
    Column("occurred_at", _TZ, nullable=False),
    # Durable total order over this table's events (same scheme as the
    # group-key events: positive and per-table-unique only; monotonic
    # transactional assignment is a future guarded-writer guarantee).
    Column("event_sequence", BigInteger, nullable=False),
    CheckConstraint("event_sequence > 0",
                    name="mapping_alias_events_event_sequence_positive"),
    UniqueConstraint("event_sequence",
                     name="mapping_alias_events_event_sequence_unique"),
    # Event-log history over the alias key: NON-UNIQUE lookup index only
    # (writer-projection boundary above).
    Index("ix_mapping_alias_events_alias_key",
          "record_type", "field_name", "scope_a", "scope_b", "old_value"),
    Index("ix_mapping_alias_events_correction_time",
          "correction_id", "occurred_at"),
    CheckConstraint(_ALIAS_ACTIONS,
                    name="mapping_alias_events_action_known"),
    CheckConstraint("length(evidence_ref) > 0",
                    name="mapping_alias_events_evidence_ref_non_empty"),
    # scope_b (the 5-part in-memory key shape) is only meaningful together
    # with scope_a.
    CheckConstraint("scope_b IS NULL OR scope_a IS NOT NULL",
                    name="mapping_alias_events_scope_b_requires_scope_a"),
)

ALL_ALIAS_TABLES = (group_key_alias_events, mapping_alias_events)
