#!/usr/bin/env python3
"""Create one synthetic source observation through the maintained G2 writer."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import sys
import uuid
from pathlib import Path
from urllib.parse import quote

import sqlalchemy as sa

sys.path.insert(0, "/opt/uvm/app")
from uvm.ingestion.run import CollectionScheduleV1
from uvm.ingestion.scheduled_collector import (
    ConfiguredFixtureClient, FileFixtureEvidenceSink, FixtureResponse,
    ScheduledCollector,
)
from uvm.persistence.ingestion_store import IngestionStore


class LocalSyntheticClient(ConfiguredFixtureClient):
    source_family = "local"


def main() -> None:
    if os.environ.get("UVM_G7_DISPOSABLE_MODE") != "1":
        raise SystemExit("disposable fixture mode required")
    dsn = os.environ.get("UVM_DB_URL")
    if not dsn:
        password_file = Path("/run/uvm-g7-secrets/uvm_db_password")
        if not password_file.is_file():
            raise SystemExit("application database configuration unavailable")
        password = quote(password_file.read_text(encoding="ascii").strip(), safe="")
        dsn = f"postgresql+psycopg://uvm_app:{password}@127.0.0.1:5432/uvm"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    record = {"observed_at": now.isoformat().replace("+00:00", "Z"),
        "native_id_scheme": "synthetic-advisory-v1", "native_id_authority": "g7-local-fixture",
        "native_id_value": "preservation-sentinel-01", "asset_locator": "asset-fixture-01",
        "component_locator": "component-fixture-01", "source_record_locator": "record-fixture-01",
        "source_rating": "informational", "vulnerability_refs": [],
        "source_first_seen_at": now.isoformat().replace("+00:00", "Z"),
        "report_id": "synthetic-report-01", "coverage_scope": "fixture-full"}
    raw = json.dumps({"fixture_schema": "uvm.synthetic.fixture.v1", "records": [record],
        "next_cursor": None, "terminal": True}, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    response = FixtureResponse(raw=raw, response_class="200", terminal=True,
        report_id="synthetic-report-01", query_scope="fixture-full")
    client = LocalSyntheticClient({None: [response]})
    schedule = CollectionScheduleV1("g7-preservation-synthetic-source", 1,
        "local", "g7-local", "all", expected_run_grace=timedelta(minutes=5),
        max_attempts=1, max_page_attempts=1, total_deadline=timedelta(minutes=1),
        freshness_rule_ref="g7-synthetic-fixture")
    engine = sa.create_engine(dsn, pool_pre_ping=True)
    try:
        collector = ScheduledCollector(IngestionStore(engine), schedule, client,
            clock=lambda: now, evidence_sink=FileFixtureEvidenceSink(
                "/opt/uvm/state/source-evidence"))
        run = collector.collect(now, run_id=str(uuid.uuid4()))
        stored = IngestionStore(engine).read_run(run.run_id)
        if run.state != "completed" or len(run.observations) != 1 or not stored["evidence"]:
            raise RuntimeError("synthetic source collection did not retain one registered observation")
        print(json.dumps({"run_id": run.run_id, "revision": run.revision,
            "state": run.state, "observation_count": len(run.observations),
            "evidence_count": len(stored["evidence"]),
            "raw_sha256": hashlib.sha256(raw).hexdigest(), "byte_size": len(raw)},
            sort_keys=True, separators=(",", ":")))
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
