"""Add revision anchors and temporal assessments (FR-ID-01/02, CR-03).

Revision ID: 0003
Revises: 0002

Frozen, self-contained DDL. Live cutover requires all identity writers to be
quiescent across final preflight/backfill and V2 writer activation.
"""

import re
import uuid
from datetime import datetime, timezone

from alembic import context, op
from alembic.util.exc import CommandError
from sqlalchemy import (
    CheckConstraint, Column, DateTime, ForeignKey, Index, Integer,
    MetaData, String, Table, UniqueConstraint, Uuid, text,
)
from sqlalchemy.schema import CreateIndex, CreateTable, DropIndex, DropTable

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

_ID = Uuid(as_uuid=False)
_TZ = DateTime(timezone=True)
_metadata = MetaData(naming_convention={
    "pk": "pk_%(table_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s",
})
Table("identity_resolutions", _metadata,
      Column("resolution_id", _ID, primary_key=True))
resolution_temporal_assessments = Table(
    "resolution_temporal_assessments", _metadata,
    Column("assessment_id", _ID, primary_key=True),
    Column("resolution_id", _ID,
           ForeignKey("identity_resolutions.resolution_id"), nullable=False),
    Column("event_sequence", Integer, nullable=False),
    Column("status", String, nullable=False),
    Column("proof_reference", String, nullable=True),
    Column("origin", String, nullable=False),
    Column("assessed_at", _TZ, nullable=False),
    Column("supersedes_assessment_id", _ID,
           ForeignKey("resolution_temporal_assessments.assessment_id"),
           nullable=True),
    Index("ix_rta_resolution_event", "resolution_id", "event_sequence"),
    Index("ix_rta_supersedes", "supersedes_assessment_id"),
    CheckConstraint("event_sequence > 0", name="rta_event_sequence_positive"),
    CheckConstraint("status IN ('verified', 'legacy_unverified')",
                    name="rta_status_known"),
    CheckConstraint("origin IN ('migration_backfill', 'reviewed')",
                    name="rta_origin_known"),
    CheckConstraint("status <> 'verified' OR (proof_reference IS NOT NULL "
                    "AND length(proof_reference) > 0)",
                    name="rta_verified_requires_proof"),
    CheckConstraint("supersedes_assessment_id IS NULL OR "
                    "supersedes_assessment_id <> assessment_id",
                    name="rta_no_self_supersession"),
    UniqueConstraint("resolution_id", "event_sequence",
                     name="rta_resolution_event"),
)

_BIRTH_CHECK = (
    "(birth_exposure_id IS NULL AND birth_exposure_revision IS NULL) "
    "OR (birth_exposure_id IS NOT NULL "
    "AND birth_exposure_revision IS NOT NULL "
    "AND birth_exposure_revision > 0)"
)
_SELECTION_CHECK = (
    "((outcome IN ('matched', 'new') "
    "AND ((schema_version = 2 "
    "AND selected_exposure_revision IS NOT NULL "
    "AND selected_occurrence_revision IS NOT NULL "
    "AND selected_exposure_revision > 0 "
    "AND selected_occurrence_revision > 0) "
    "OR (schema_version = 1 "
    "AND ((selected_exposure_revision IS NULL "
    "AND selected_occurrence_revision IS NULL) "
    "OR (selected_exposure_revision IS NOT NULL "
    "AND selected_occurrence_revision IS NOT NULL "
    "AND selected_exposure_revision > 0 "
    "AND selected_occurrence_revision > 0))))) "
    "OR (outcome IN ('ambiguous', 'unresolved') "
    "AND selected_exposure_revision IS NULL "
    "AND selected_occurrence_revision IS NULL))"
)
_BIRTH_NAME = "occurrences_birth_anchor_consistent"
_SELECTION_NAME = "identity_resolutions_selection_anchors_consistent"
_VERSION_NAME = "identity_resolutions_schema_version_known"
_OLD_VERSION_NAME = "identity_resolutions_schema_version_v1"
_BIRTH_FK = "fk_occurrences_birth_exposure_id_exposures"


def _dialect() -> str:
    name = op.get_bind().dialect.name
    if name not in ("sqlite", "postgresql"):
        raise CommandError(f"0003 does not support {name}")
    return name


def _correlated_membership_correction(bind, row) -> bool:
    """Validate recorded V1 history without treating revisions as shared.

    The resolution's workload/incarnation are historical values.  Current
    occurrence values may differ only when both append-only correction
    streams are complete and their membership moves correlate in order.
    Independent field corrections advance only their own record's revision.
    """
    def canonical_identifier(value):
        if value is None:
            return None
        try:
            parsed = uuid.UUID(str(value))
        except (ValueError, TypeError, AttributeError):
            return None
        return str(value) if str(parsed) == str(value) else None

    def identifier(value):
        return str(value).replace("-", "") if value is not None else None

    def transitions(record_type, record_id, revision):
        rows = bind.execute(text(
            "SELECT field_name, old_value, new_value, correlation_id, "
            "previous_revision, new_revision "
            "FROM correction_records WHERE record_type=:type "
            "AND record_id=:id ORDER BY previous_revision"
        ), {"type": record_type, "id": record_id}).mappings().all()
        if not rows:
            return [], []
        membership_field = ("workload_id" if record_type == "exposure"
                            else "incarnation_id")
        if any(
                r["field_name"] == membership_field
                and (canonical_identifier(r["old_value"]) is None
                     or canonical_identifier(r["new_value"]) is None)
                for r in rows):
            return None
        if any(r["field_name"] == membership_field
               and r["previous_revision"] == 0 for r in rows):
            return None
        steps = [r for r in rows
                 if (r["previous_revision"], r["new_revision"]) != (0, 0)]
        if (not isinstance(revision, int) or revision < 1
                or len(steps) != revision - 1):
            return None
        steps.sort(key=lambda r: r["previous_revision"])
        if any(r["previous_revision"] != n
               or r["new_revision"] != n + 1
               for n, r in enumerate(steps, start=1)):
            return None
        return rows, [r for r in steps if r["field_name"] == membership_field]

    exposure_history = transitions(
        "exposure", row["exposure_id"], row["exposure_revision"])
    occurrence_history = transitions(
        "occurrence", row["occurrence_id"], row["occurrence_revision"])
    if exposure_history is None or occurrence_history is None:
        return False
    exposure_rows, exposure_steps = exposure_history
    occurrence_rows, occurrence_steps = occurrence_history
    unchanged = (row["current_workload"] == row["selected_workload"]
                 and row["occurrence_workload"] == row["selected_workload"]
                 and row["current_incarnation"] == row["selected_incarnation"])
    # A pre-existing unchanged row with no correction records may have a
    # revision > 1 but no reconstructable timing. Keep it unverified rather
    # than inventing a correction sequence or a selection anchor.
    if not exposure_rows and not occurrence_rows:
        return unchanged
    if ((not exposure_rows and row["exposure_revision"] != 1)
            or (not occurrence_rows and row["occurrence_revision"] != 1)):
        return False

    def incarnation_workload(incarnation_id):
        if incarnation_id is None:
            return None
        value = bind.execute(text(
            "SELECT workload_id FROM incarnations WHERE incarnation_id=:id"
        ), {"id": incarnation_id}).scalar_one_or_none()
        return identifier(value)

    # A correlation ID identifies one logical membership move.  Reusing it
    # remains malformed even when there is no occurrence stream to pair.
    move_correlations = [step["correlation_id"]
                         for step in exposure_steps]
    if len(set(move_correlations)) != len(move_correlations):
        return False

    # Every post-correction exposure workload phase must have been retained
    # by 0002.  A missing intermediate pair is FK-clean when the selected
    # row points at a later phase, but it leaves an uncheckable historical
    # membership gap and must refuse the cutover.
    if exposure_steps:
        for step in exposure_steps:
            phase = identifier(step["new_value"])
            retained = bind.execute(text(
                "SELECT 1 FROM exposure_workload_memberships "
                "WHERE exposure_id=:exposure_id AND workload_id=:workload_id"
            ), {"exposure_id": row["exposure_id"],
                "workload_id": phase}).scalar_one_or_none()
            if phase is None or retained is None:
                return False

    # A V1 occurrence may have been created after an earlier exposure
    # membership move.  In that case its first persisted state is already
    # the current membership, so there is no occurrence-side move to pair
    # with the exposure move.  Accept only the conservative shape where the
    # selected/current values agree at the end of a valid exposure stream;
    # locator-only occurrence corrections still have to pass the complete
    # occurrence revision-chain validation above.  This is missing temporal
    # evidence, not proof of an anchor.
    if exposure_steps and not occurrence_steps:
        if (row["selected_workload"] != row["current_workload"]
                or row["occurrence_workload"] != row["current_workload"]
                or row["selected_incarnation"] != row["current_incarnation"]):
            return False
        workload = identifier(exposure_steps[0]["old_value"])
        if workload is None:
            return False
        for step in exposure_steps:
            if (step["field_name"] != "workload_id"
                    or identifier(step["old_value"]) != workload):
                return False
            workload = identifier(step["new_value"])
            if workload is None:
                return False
        if (workload != identifier(row["current_workload"])
                or workload != identifier(row["selected_workload"])
                or incarnation_workload(
                    identifier(row["current_incarnation"])) != workload):
            return False
        return True
    # An occurrence may have been created after an exposure-side prefix of
    # membership moves.  Only the ordered suffix after that birth can be
    # paired, and the retained V1 selection must identify the state at the
    # suffix boundary.  An occurrence-side prefix has no corresponding
    # exposure birth evidence and remains a contradiction.
    if len(exposure_steps) < len(occurrence_steps):
        return False
    prefix_length = len(exposure_steps) - len(occurrence_steps)
    if prefix_length:
        prefix_steps = exposure_steps[:prefix_length]
        prefix_workload = identifier(prefix_steps[0]["old_value"])
        if prefix_workload is None:
            return False
        for step in prefix_steps:
            if (step["field_name"] != "workload_id"
                    or identifier(step["old_value"]) != prefix_workload):
                return False
            prefix_workload = identifier(step["new_value"])
            if prefix_workload is None:
                return False
        if (prefix_workload != identifier(row["selected_workload"])
                or not occurrence_steps
                or identifier(occurrence_steps[0]["old_value"])
                != identifier(row["selected_incarnation"])
                or incarnation_workload(
                    identifier(row["selected_incarnation"]))
                != prefix_workload):
            return False

    # A correlation ID identifies one logical membership move across the
    # exposure and occurrence streams.  Reusing it for a later move makes
    # the append-only history ambiguous, even when every record revision is
    # otherwise contiguous.
    paired_exposure_steps = exposure_steps[prefix_length:]
    workload = (identifier(paired_exposure_steps[0]["old_value"])
                if exposure_steps else identifier(row["current_workload"]))
    incarnation = (identifier(occurrence_steps[0]["old_value"])
                   if occurrence_steps else identifier(row["current_incarnation"]))
    selected_workload = identifier(row["selected_workload"])
    selected_incarnation = identifier(row["selected_incarnation"])
    selected_seen = (workload == selected_workload
                     and incarnation == selected_incarnation)

    if incarnation_workload(incarnation) != workload:
        return False
    for exposure_step, occurrence_step in zip(
            paired_exposure_steps, occurrence_steps):
        if (exposure_step["correlation_id"]
                != occurrence_step["correlation_id"]
                or identifier(exposure_step["old_value"]) != workload
                or identifier(occurrence_step["old_value"]) != incarnation):
            return False
        workload = identifier(exposure_step["new_value"])
        incarnation = identifier(occurrence_step["new_value"])
        if incarnation_workload(incarnation) != workload:
            return False
        selected_seen |= (workload == selected_workload
                          and incarnation == selected_incarnation)
    result = (selected_seen
              and workload == identifier(row["current_workload"])
              and incarnation == identifier(row["current_incarnation"])
              and identifier(row["occurrence_workload"]) == workload)
    return result


def _preflight() -> None:
    bind = op.get_bind()
    if _dialect() == "sqlite":
        violations = bind.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise CommandError(
                f"refusing 0003: existing foreign-key violations: {violations[:3]}")
    # Existing selected references must form a coherent retained chain.  A
    # correlated correction may move current membership after the V1
    # selection; in that case validate its append-only history instead of
    # comparing the historical selection with current values.
    rows = bind.execute(text(
        "SELECT r.resolution_id, r.exposure_id, r.occurrence_id, "
        "r.workload_id AS selected_workload, "
        "r.incarnation_id AS selected_incarnation, "
        "e.group_id, e.workload_id AS current_workload, "
        "e.revision AS exposure_revision, "
        "o.incarnation_id AS current_incarnation, "
        "o.workload_id AS occurrence_workload, "
        "o.revision AS occurrence_revision, "
        "CASE WHEN e.exposure_id IS NULL OR i.incarnation_id IS NULL "
        "OR o.occurrence_id IS NULL OR m.exposure_id IS NULL THEN 1 "
        "WHEN e.group_id <> r.group_id "
        "OR i.workload_id <> r.workload_id "
        "OR o.exposure_id <> r.exposure_id THEN 1 ELSE 0 END AS base_bad "
        "FROM identity_resolutions AS r "
        "LEFT JOIN exposures AS e ON e.exposure_id = r.exposure_id "
        "LEFT JOIN incarnations AS i ON i.incarnation_id = r.incarnation_id "
        "LEFT JOIN occurrences AS o ON o.occurrence_id = r.occurrence_id "
        "LEFT JOIN exposure_workload_memberships AS m "
        "ON m.exposure_id = r.exposure_id AND m.workload_id = r.workload_id "
        "WHERE r.outcome IN ('matched', 'new')"
    )).mappings().all()
    bad = 0
    for row in rows:
        if row["base_bad"]:
            bad += 1
            continue
        if not _correlated_membership_correction(bind, row):
            bad += 1
    if bad:
        raise CommandError(
            f"refusing 0003: {bad} selected identity chain(s) inconsistent")
    versions = bind.execute(text(
        "SELECT COUNT(*) FROM identity_resolutions WHERE schema_version <> 1"
    )).scalar_one()
    if versions:
        raise CommandError("refusing 0003: unexpected legacy schema version")


def _sqlite_rebuild(table: str, *, forward: bool) -> None:
    """Rebuild one table inside env.py's FK-off-before-BEGIN transaction."""
    bind = op.get_bind()
    ddl = bind.execute(text(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=:table"
    ), {"table": table}).scalar_one()
    indexes = [row[0] for row in bind.execute(text(
        "SELECT sql FROM sqlite_master WHERE type='index' "
        "AND tbl_name=:table AND sql IS NOT NULL ORDER BY name"
    ), {"table": table})]
    temp = table + "__0003"
    ddl, count = re.subn(r'CREATE TABLE "?' + table + r'"? \(',
                         f"CREATE TABLE {temp} (", ddl, count=1)
    if count != 1:
        raise CommandError(f"unexpected {table} DDL")
    if table == "occurrences":
        additions = [
            "birth_exposure_id CHAR(32)",
            "birth_exposure_revision INTEGER",
            f"CONSTRAINT {_BIRTH_FK} FOREIGN KEY(birth_exposure_id) "
            "REFERENCES exposures (exposure_id)",
            f"CONSTRAINT {_BIRTH_NAME} CHECK ({_BIRTH_CHECK})",
        ]
        removed_names = ("birth_exposure_id", "birth_exposure_revision",
                         _BIRTH_FK, _BIRTH_NAME)
    else:
        additions = [
            "selected_exposure_revision INTEGER",
            "selected_occurrence_revision INTEGER",
            f"CONSTRAINT {_VERSION_NAME} CHECK (schema_version IN (1, 2))",
            f"CONSTRAINT {_SELECTION_NAME} CHECK ({_SELECTION_CHECK})",
        ]
        removed_names = ("selected_exposure_revision",
                         "selected_occurrence_revision", _SELECTION_NAME)
        # Preserve the self-FK across the rename/drop; 0002 uses this route.
        ddl, self_refs = re.subn(
            r'REFERENCES "?identity_resolutions"? \(resolution_id\)',
            f"REFERENCES {temp} (resolution_id)", ddl, count=1)
        if self_refs != 1:
            raise CommandError("unexpected resolution self-FK DDL")
    if forward:
        if table == "identity_resolutions":
            old = (f"CONSTRAINT {_OLD_VERSION_NAME} "
                   "CHECK (schema_version = 1)")
            if ddl.count(old) != 1:
                raise CommandError("unexpected legacy version CHECK")
            ddl = ddl.replace(old, additions[2], 1)
            additions.pop(2)
        if table == "occurrences":
            # SQLite requires columns before table-level constraints.
            first_constraint = ddl.index("CONSTRAINT pk_occurrences")
            ddl = (ddl[:first_constraint]
                   + ", ".join(additions[:2]) + ", \n\t"
                   + ddl[first_constraint:])
            additions = additions[2:]
        else:
            first_constraint = ddl.index("CONSTRAINT pk_identity_resolutions")
            ddl = (ddl[:first_constraint]
                   + ", ".join(additions[:2]) + ", \n\t"
                   + ddl[first_constraint:])
            additions = additions[2:]
        ddl = ddl[:ddl.rfind(")")] + ",\n\t" + ",\n\t".join(additions) + "\n)"
    else:
        # Remove the exact additions this frozen revision emitted. SQLite
        # may reformat identifiers during RENAME but keeps constraint text.
        for name in removed_names:
            pattern = rf',\s*(?:CONSTRAINT )?{re.escape(name)}\b[^,]*'
            if name == _BIRTH_NAME or name == _SELECTION_NAME:
                # CHECK text contains commas and nested parentheses; remove
                # by finding its balanced closing parenthesis below.
                start = re.search(rf',\s*CONSTRAINT {name} CHECK \(', ddl)
                if start is None:
                    raise CommandError(f"missing 0003 constraint {name}")
                pos = start.end() - 1
                depth = 0
                for end in range(pos, len(ddl)):
                    if ddl[end] == "(":
                        depth += 1
                    elif ddl[end] == ")":
                        depth -= 1
                        if depth == 0:
                            ddl = ddl[:start.start()] + ddl[end + 1:]
                            break
                else:
                    raise CommandError(f"unbalanced 0003 constraint {name}")
            else:
                ddl, n = re.subn(pattern, "", ddl, count=1)
                if n != 1:
                    raise CommandError(f"missing 0003 addition {name}")
        if table == "identity_resolutions":
            new = f"CONSTRAINT {_VERSION_NAME} CHECK (schema_version IN (1, 2))"
            if ddl.count(new) != 1:
                raise CommandError("unexpected V2 version CHECK")
            ddl = ddl.replace(new,
                              f"CONSTRAINT {_OLD_VERSION_NAME} "
                              "CHECK (schema_version = 1)", 1)
    columns = [row[1] for row in bind.exec_driver_sql(
        f"PRAGMA table_info({table})")]
    if not forward:
        columns = [col for col in columns if col not in removed_names]
    names = ", ".join(columns)
    bind.exec_driver_sql(ddl)
    bind.exec_driver_sql(
        f"INSERT INTO {temp} ({names}) SELECT {names} FROM {table}")
    bind.exec_driver_sql(f"DROP TABLE {table}")
    bind.exec_driver_sql(f"ALTER TABLE {temp} RENAME TO {table}")
    for index_sql in indexes:
        bind.exec_driver_sql(index_sql)
    violations = bind.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise CommandError(
            f"0003 {table} rebuild failed foreign_key_check: {violations[:3]}")


def _pg_upgrade() -> None:
    op.execute(text(
        "ALTER TABLE occurrences "
        "ADD COLUMN birth_exposure_id UUID, "
        "ADD COLUMN birth_exposure_revision INTEGER, "
        f"ADD CONSTRAINT {_BIRTH_FK} FOREIGN KEY (birth_exposure_id) "
        "REFERENCES exposures (exposure_id), "
        f"ADD CONSTRAINT {_BIRTH_NAME} CHECK ({_BIRTH_CHECK})"
    ))
    op.execute(text(
        "ALTER TABLE identity_resolutions "
        "ADD COLUMN selected_exposure_revision INTEGER, "
        "ADD COLUMN selected_occurrence_revision INTEGER, "
        f"DROP CONSTRAINT {_OLD_VERSION_NAME}, "
        f"ADD CONSTRAINT {_VERSION_NAME} CHECK (schema_version IN (1, 2)), "
        f"ADD CONSTRAINT {_SELECTION_NAME} CHECK ({_SELECTION_CHECK})"
    ))


def _pg_downgrade() -> None:
    op.execute(text(
        "ALTER TABLE identity_resolutions "
        f"DROP CONSTRAINT {_SELECTION_NAME}, "
        f"DROP CONSTRAINT {_VERSION_NAME}, "
        f"ADD CONSTRAINT {_OLD_VERSION_NAME} CHECK (schema_version = 1), "
        "DROP COLUMN selected_exposure_revision, "
        "DROP COLUMN selected_occurrence_revision"
    ))
    op.execute(text(
        "ALTER TABLE occurrences "
        f"DROP CONSTRAINT {_BIRTH_NAME}, "
        f"DROP CONSTRAINT {_BIRTH_FK}, "
        "DROP COLUMN birth_exposure_id, "
        "DROP COLUMN birth_exposure_revision"
    ))


def _backfill() -> None:
    bind = op.get_bind()
    # All three current revisions at 1, a stable selected chain, and no
    # correction evidence are necessary for the uniquely proved case.
    rows = bind.execute(text(
        "SELECT r.resolution_id, r.exposure_id, r.occurrence_id, "
        "e.revision AS exposure_revision, o.revision AS occurrence_revision, "
        "i.revision AS incarnation_revision, e.workload_id AS current_workload, "
        "r.workload_id AS selected_workload, "
        "(SELECT COUNT(*) FROM correction_records c WHERE "
        "(c.record_type = 'exposure' AND c.record_id = r.exposure_id) OR "
        "(c.record_type = 'occurrence' AND c.record_id = r.occurrence_id) OR "
        "(c.record_type = 'incarnation' AND c.record_id = r.incarnation_id)) "
        "AS corrections "
        "FROM identity_resolutions r "
        "JOIN exposures e ON e.exposure_id = r.exposure_id "
        "JOIN occurrences o ON o.occurrence_id = r.occurrence_id "
        "JOIN incarnations i ON i.incarnation_id = r.incarnation_id "
        "WHERE r.schema_version = 1 AND r.outcome IN ('matched', 'new') "
        "ORDER BY r.resolution_id"
    )).mappings().all()
    for row in rows:
        verified = (
            row["exposure_revision"] == 1
            and row["occurrence_revision"] == 1
            and row["incarnation_revision"] == 1
            and row["current_workload"] == row["selected_workload"]
            and row["corrections"] == 0
        )
        if verified:
            bind.execute(text(
                "UPDATE identity_resolutions SET "
                "selected_exposure_revision=1, selected_occurrence_revision=1 "
                "WHERE resolution_id=:id"
            ), {"id": row["resolution_id"]})
        bind.execute(text(
            "INSERT INTO resolution_temporal_assessments "
            "(assessment_id, resolution_id, event_sequence, status, "
            "proof_reference, origin, assessed_at, supersedes_assessment_id) "
            "VALUES (:assessment_id, :resolution_id, 1, :status, "
            ":proof, 'migration_backfill', :assessed_at, NULL)"
        ), {
            "assessment_id": uuid.uuid4().hex,
            "resolution_id": row["resolution_id"],
            "status": "verified" if verified else "legacy_unverified",
            "proof": "migration:0003:unchanged_revision_1:v1" if verified else None,
            "assessed_at": datetime.now(timezone.utc),
        })


def _downgrade_guard() -> None:
    bind = op.get_bind()
    checks = [
        ("V2 resolution", "SELECT COUNT(*) FROM identity_resolutions "
         "WHERE schema_version = 2"),
        ("selection anchor", "SELECT COUNT(*) FROM identity_resolutions "
         "WHERE selected_exposure_revision IS NOT NULL "
         "OR selected_occurrence_revision IS NOT NULL"),
        ("birth anchor", "SELECT COUNT(*) FROM occurrences "
         "WHERE birth_exposure_id IS NOT NULL "
         "OR birth_exposure_revision IS NOT NULL"),
        ("nonreproducible assessment",
         "SELECT COUNT(*) FROM resolution_temporal_assessments "
         "WHERE status <> 'legacy_unverified' "
         "OR origin <> 'migration_backfill' "
         "OR proof_reference IS NOT NULL "
         "OR event_sequence <> 1 OR supersedes_assessment_id IS NOT NULL"),
    ]
    for label, query in checks:
        count = bind.execute(text(query)).scalar_one()
        if count:
            raise CommandError(
                f"refusing 0003 downgrade: {count} {label} row(s) would lose data")
    # A reproducible migration event must correspond exactly to one retained
    # selected V1 row. Refuse alien/missing events before dropping the table.
    discrepancy = bind.execute(text(
        "SELECT COUNT(*) FROM identity_resolutions r "
        "LEFT JOIN resolution_temporal_assessments a "
        "ON a.resolution_id = r.resolution_id "
        "WHERE r.outcome IN ('matched','new') "
        "AND (r.schema_version <> 1 OR a.assessment_id IS NULL)"
    )).scalar_one()
    alien = bind.execute(text(
        "SELECT COUNT(*) FROM resolution_temporal_assessments a "
        "LEFT JOIN identity_resolutions r ON r.resolution_id = a.resolution_id "
        "WHERE r.resolution_id IS NULL OR r.outcome NOT IN ('matched','new')"
    )).scalar_one()
    if discrepancy or alien:
        raise CommandError("refusing 0003 downgrade: assessment stream is not reproducible")


def upgrade() -> None:
    if context.is_offline_mode():
        raise CommandError("0003 upgrade requires online preflight and backfill")
    _preflight()
    if _dialect() == "sqlite":
        _sqlite_rebuild("occurrences", forward=True)
        _sqlite_rebuild("identity_resolutions", forward=True)
    else:
        _pg_upgrade()
    op.execute(CreateTable(resolution_temporal_assessments))
    for index in sorted(resolution_temporal_assessments.indexes,
                        key=lambda item: item.name):
        op.execute(CreateIndex(index))
    _backfill()


def downgrade() -> None:
    if context.is_offline_mode():
        raise CommandError("0003 downgrade requires online safety checks")
    _dialect()
    _downgrade_guard()
    for index in sorted(resolution_temporal_assessments.indexes,
                        key=lambda item: item.name, reverse=True):
        op.execute(DropIndex(index))
    op.execute(DropTable(resolution_temporal_assessments))
    if _dialect() == "sqlite":
        _sqlite_rebuild("identity_resolutions", forward=False)
        _sqlite_rebuild("occurrences", forward=False)
    else:
        _pg_downgrade()
