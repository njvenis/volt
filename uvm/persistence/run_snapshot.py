"""One-transaction historical read model for a retained source run.

This module is intentionally read-only.  It composes the observation and
identity stores on one connection so a caller receives an internally
consistent historical view, not a claim about the current database after the
method returns.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import sqlalchemy as sa

from uvm.persistence.identity_resolution_store import (
    IdentityResolutionReadError, IdentityResolutionReadResult,
    IdentityResolutionStore,
)
from uvm.persistence.observation_schema import source_observations
from uvm.persistence.observation_store import (
    ObservationReadError, ObservationRepository, RetainedRun,
)

UTC = timezone.utc


@dataclass(frozen=True)
class RetainedObservationResolution:
    """Resolution history/status captured for one retained observation."""

    observation_id: str
    history: tuple
    head: object | None
    status: str
    statuses: tuple = ()
    proof_reference: str | None = None


@dataclass(frozen=True)
class RunSnapshot:
    """Immutable historical-at-read-time run snapshot.

    ``read_at`` labels when this view was captured.  It is not a currency,
    seal, manifest or assertion about state after the read transaction.
    """

    source_account_id: str
    run_id: str
    retained_run: RetainedRun
    resolutions: tuple[RetainedObservationResolution, ...]
    read_at: datetime
    historical: bool = True


class RunSnapshotReadError(ValueError):
    """The requested snapshot cannot be proven from one coherent read."""


class RunSnapshotStore:
    def __init__(self, engine):
        self._engine = engine
        self._observations = ObservationRepository(engine)
        self._resolutions = IdentityResolutionStore(engine)

    def read(self, source_account_id: str, run_id: str) -> RunSnapshot:
        """Read observations, holders and resolution histories in one scope."""
        conn = self._engine.connect()
        if conn.dialect.name == "postgresql":
            conn = conn.execution_options(isolation_level="REPEATABLE READ")
            conn.begin()
        elif conn.dialect.name == "sqlite":
            conn.exec_driver_sql("BEGIN")
        else:
            conn.begin()
        try:
            retained = self._observations._read_run_on_connection(
                conn, source_account_id, run_id)
            observation_ids = {
                row.observation.observation_id for row in retained.rows
            }
            # Holder rows outside the requested run are needed to validate
            # quarantine retention, but their identity-resolution histories
            # are outside this account/run's disclosure scope.
            holder_positions = {}
            selected_positions = {
                (row.observation.source_account_id,
                 row.observation.run_id,
                 row.observation.source_record_ordinal)
                for row in retained.rows
            }
            for record in retained.quarantine:
                for position, observation_id in zip(
                        record.positions, record.retained_ids):
                    holder_positions.setdefault(observation_id, set()).add(position)
                if not any(position in selected_positions
                           for position in record.positions):
                    raise RunSnapshotReadError(
                        "quarantine record has no holder in selected run")
            if holder_positions:
                holder_rows = conn.execute(sa.select(
                    source_observations.c.observation_id,
                    source_observations.c.source_account_id,
                    source_observations.c.run_id,
                    source_observations.c.source_record_ordinal,
                ).where(source_observations.c.observation_id.in_(
                    tuple(holder_positions)))).mappings().all()
                if len(holder_rows) != len(holder_positions):
                    raise RunSnapshotReadError(
                        "quarantine holder set references missing observations")
                for row in holder_rows:
                    actual = (row["source_account_id"], row["run_id"],
                              row["source_record_ordinal"])
                    if actual not in holder_positions[row["observation_id"]]:
                        raise RunSnapshotReadError(
                            "quarantine holder does not match its declared position")

            histories = self._resolutions.read_observation_history(
                conn, tuple(sorted(observation_ids)))
            resolution_rows = []
            for observation_id in sorted(observation_ids):
                history, statuses, status = histories[observation_id]
                if status is None:
                    resolution_rows.append(RetainedObservationResolution(
                        observation_id, (), None, "not_present", ()))
                else:
                    resolution_rows.append(RetainedObservationResolution(
                        observation_id, history, history[-1], status.status,
                        statuses, status.proof_reference))
            return RunSnapshot(
                source_account_id, run_id, retained, tuple(resolution_rows),
                datetime.now(UTC), True)
        except (ObservationReadError, IdentityResolutionReadError,
                RunSnapshotReadError) as exc:
            raise RunSnapshotReadError(str(exc)) from exc
        finally:
            conn.rollback()
            conn.close()
