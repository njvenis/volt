#!/usr/bin/env python3
"""Exercise G7 0058→0061 migration commits and rollback on real PostgreSQL."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import uuid


def run(command: list[str], evidence: Path, name: str, *, stdin: bytes | None = None,
        expect: int | None = 0) -> subprocess.CompletedProcess:
    result = subprocess.run(command, input=stdin, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False)
    (evidence / f"{name}.stdout").write_bytes(result.stdout)
    (evidence / f"{name}.stderr").write_bytes(result.stderr)
    (evidence / f"{name}.exit").write_text(f"{result.returncode}\n")
    if expect is not None and result.returncode != expect:
        raise RuntimeError(f"{name} exited {result.returncode}, expected {expect}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    root = args.evidence
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = f"volt-g7-schema-probe-{args.run_id}"
    token = str(uuid.uuid4())
    run_id = str(uuid.uuid4())
    evidence_id = str(uuid.uuid4())
    expected_row = {"evidence_id": evidence_id, "schema_version": 1,
        "run_id": run_id, "run_revision": 1, "evidence_ref": "fixture/evidence",
        "sha256": "a" * 64, "kind": "page", "registered_at": "2026-10-29T12:00:00+00:00"}
    container_created = False
    try:
        command = ["docker", "run", "-d", "--name", name,
            "--label", "uvm.g7.schema-migration-probe=true",
            "--label", f"uvm.g7.run-id={args.run_id}",
            "--network", "none", "--tmpfs", "/var/lib/postgresql/data:rw,uid=101,gid=103,mode=0700",
            "--user", "postgres", "--entrypoint", "/bin/bash", args.image, "-lc",
            "if [[ ! -s /var/lib/postgresql/data/PG_VERSION ]]; then "
            "/usr/lib/postgresql/18/bin/initdb -D /var/lib/postgresql/data "
            "--auth-local=trust --auth-host=trust --encoding=UTF8 --locale=C >/dev/null; fi; "
            "exec /usr/lib/postgresql/18/bin/postgres -D /var/lib/postgresql/data -h 127.0.0.1 -p 5432"]
        created = run(command, root, "postgres-container-start")
        container_created = True
        (root / "container-id.txt").write_bytes(created.stdout)
        for attempt in range(90):
            ready = subprocess.run(["docker", "exec", name,
                "/usr/lib/postgresql/18/bin/pg_isready", "-h", "127.0.0.1", "-p", "5432"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if ready.returncode == 0:
                (root / "postgres-ready.stdout").write_bytes(ready.stdout)
                break
        else:
            raise RuntimeError("disposable probe PostgreSQL did not become ready")

        setup = f"""CREATE DATABASE g7_probe_base;
\\connect g7_probe_base
CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY);
INSERT INTO alembic_version VALUES ('0058');
CREATE TABLE collection_runs (run_id UUID NOT NULL, revision INTEGER NOT NULL,
  CONSTRAINT uq_collection_runs_revision UNIQUE (run_id, revision));
CREATE TABLE ingestion_evidence (
  evidence_id UUID PRIMARY KEY, schema_version INTEGER NOT NULL, run_id UUID NOT NULL,
  run_revision INTEGER NOT NULL, evidence_ref VARCHAR NOT NULL, sha256 VARCHAR NOT NULL,
  kind VARCHAR NOT NULL, registered_at TIMESTAMP WITH TIME ZONE NOT NULL,
  CONSTRAINT fk_ingestion_evidence_run FOREIGN KEY (run_id, run_revision)
    REFERENCES collection_runs (run_id, revision),
  CONSTRAINT ingestion_evidence_shape CHECK (schema_version = 1 AND length(sha256) = 64));
INSERT INTO collection_runs VALUES ('{run_id}', 1);
INSERT INTO ingestion_evidence VALUES ('{evidence_id}', 1, '{run_id}', 1,
  'fixture/evidence', '{'a' * 64}', 'page', '2026-10-29T12:00:00Z');
""".encode()
        run(["docker", "exec", "-i", name, "/usr/bin/psql", "-X", "-v",
            "ON_ERROR_STOP=1", "-U", "postgres", "-h", "127.0.0.1", "-d", "postgres"],
            root, "postgres-baseline-setup", stdin=setup)

        query = f"""SELECT json_build_object(
 'heads',(SELECT array_agg(version_num ORDER BY version_num) FROM alembic_version),
 'projection_table',to_regclass('public.g7_backup_projection_evidence') IS NOT NULL,
 'reservation_table',to_regclass('public.collection_request_reservations') IS NOT NULL,
 'byte_size',EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='ingestion_evidence' AND column_name='byte_size'),
 'row',(SELECT to_jsonb(e) FROM ingestion_evidence e WHERE evidence_id='{evidence_id}'::uuid))::text"""

        def inspect_database(db: str, label: str) -> dict:
            result = run(["docker", "exec", name, "/usr/bin/psql", "-X", "-A", "-t",
                "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-h", "127.0.0.1",
                "-d", db, "-c", query], root, label)
            value = json.loads(result.stdout.decode().strip())
            (root / f"{label}.json").write_text(json.dumps(value, sort_keys=True) + "\n")
            return value

        baseline = inspect_database("g7_probe_base", "baseline-state")
        expected_baseline = {"heads": ["0058"], "projection_table": False,
            "reservation_table": False, "byte_size": False, "row": expected_row}
        if baseline != expected_baseline:
            raise RuntimeError("probe baseline did not match its exact 0058 fixture")

        for revision in ("0059", "0060", "0061"):
            database = f"g7_fail_{revision}"
            run(["docker", "exec", name, "/usr/bin/createdb", "-U", "postgres",
                "-h", "127.0.0.1", "-T", "g7_probe_base", database], root,
                f"clone-before-fail-{revision}")
            failed = run(["docker", "exec", "-e",
                f"UVM_DB_URL=postgresql+psycopg://postgres@127.0.0.1:5432/{database}",
                "-e", f"UVM_G7_TEST_FAIL_AFTER_REVISION={revision}", "--user", "uvm", name,
                "/bin/bash", "-lc", "cd /opt/uvm/app && /opt/uvm/venv/bin/python -m alembic -c alembic.ini upgrade 0061"],
                root, f"fail-after-{revision}", expect=None)
            if failed.returncode == 0 or f"G7_TEST_MIGRATION_BOUNDARY_FAILURE revision={revision}".encode() not in failed.stderr:
                raise RuntimeError(f"Alembic did not inject the requested {revision} transaction failure")
            state = inspect_database(database, f"state-after-fail-{revision}")
            if state != expected_baseline:
                raise RuntimeError(f"{revision} migration failure left partial schema or row state")

        run(["docker", "exec", name, "/usr/bin/createdb", "-U", "postgres",
            "-h", "127.0.0.1", "-T", "g7_probe_base", "g7_probe_success"], root,
            "clone-before-success")
        success = run(["docker", "exec", "-e",
            "UVM_DB_URL=postgresql+psycopg://postgres@127.0.0.1:5432/g7_probe_success",
            "--user", "uvm", name, "/bin/bash", "-lc",
            "cd /opt/uvm/app && /opt/uvm/venv/bin/python -m alembic -c alembic.ini upgrade 0061"],
            root, "success-0061-upgrade")
        state = inspect_database("g7_probe_success", "state-after-success")
        expected_success_row = {**expected_row, "byte_size": None}
        expected_success = {"heads": ["0061"], "projection_table": True,
            "reservation_table": True, "byte_size": True, "row": expected_success_row}
        if state != expected_success:
            raise RuntimeError("successful Alembic transition changed old evidence or missed exact 0061 state")
        run(["docker", "exec", name, "mkdir", "-p", "/tmp/tools"],
            root, "create-inventory-probe-tools")
        run(["docker", "cp", "tools/g7_product_inventory.py",
            f"{name}:/tmp/tools/g7_product_inventory.py"], root, "copy-inventory-capture")
        run(["docker", "cp", "tools/g7_inventory_expectation.py",
            f"{name}:/tmp/tools/g7_inventory_expectation.py"], root, "copy-inventory-expectation")
        type_probe = """import json,sys
sys.path.insert(0,'/tmp')
sys.path.insert(0,'/opt/uvm/app')
from tools.g7_product_inventory import database_inventory
from tools.g7_inventory_expectation import _migration_table_record
from uvm.persistence.ingestion_schema import collection_request_reservations, ingestion_evidence
url='postgresql+psycopg://postgres@127.0.0.1:5432/g7_probe_success'
actual=database_inventory(url)
expected={'collection_request_reservations':_migration_table_record(collection_request_reservations),
 'ingestion_evidence':_migration_table_record(ingestion_evidence)}
columns=(('collection_request_reservations','reserved_at'),
 ('ingestion_evidence','registered_at'),('ingestion_evidence','byte_size'))
captured={}
for table,column in columns:
 actual_column=next(c for c in actual[table]['columns'] if c['name']==column)
 expected_column=next(c for c in expected[table]['columns'] if c['name']==column)
 actual_type=actual_column['type']; expected_type=expected_column['type']
 captured[f'{table}.{column}']={'actual_type':actual_type,'expected_type':expected_type,
  'actual_nullable':actual_column['nullable'],'expected_nullable':expected_column['nullable']}
 if actual_type!=expected_type or actual_column['nullable']!=expected_column['nullable']:
  raise SystemExit('PostgreSQL capture and migration expectation disagree on timezone semantics')
 if column in ('reserved_at','registered_at') and actual_type!='TIMESTAMP WITH TIME ZONE':
  raise SystemExit('PostgreSQL capture lost timestamp timezone semantics')
json.dump({'passed':True,'types':captured},sys.stdout,sort_keys=True,separators=(',',':'))
"""
        captured_types = run(["docker", "exec", "--user", "uvm", name, "/opt/uvm/venv/bin/python",
            "-c", type_probe], root, "actual-inventory-timezone-types")
        type_value = json.loads(captured_types.stdout.decode())
        if type_value.get("passed") is not True:
            raise RuntimeError("actual inventory capture did not prove PostgreSQL timezone semantics")
        (root / "actual-inventory-timezone-types.json").write_text(
            json.dumps(type_value, sort_keys=True, separators=(",", ":")) + "\n")
        (root / "probe-result.json").write_text(json.dumps({"passed": True,
            "postgres_image_id": args.image, "tested_revision": "0058→0061",
            "failure_boundaries": ["0059", "0060", "0061"],
            "each_failure_restored_exact_0058_state": True,
            "successful_upgrade_preserved_old_evidence_with_null_byte_size": True,
            "success_stdout_sha256": __import__("hashlib").sha256(success.stdout).hexdigest()},
            sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    finally:
        cleanup = subprocess.run(["docker", "rm", "-f", name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (root / "cleanup.stdout").write_bytes(cleanup.stdout)
        (root / "cleanup.stderr").write_bytes(cleanup.stderr)
        inspection = subprocess.run(["docker", "inspect", name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (root / "cleanup-inspect.stdout").write_bytes(inspection.stdout)
        (root / "cleanup-inspect.exit").write_text(f"{inspection.returncode}\n")
        (root / "cleanup.json").write_text(json.dumps({"container_created": container_created,
            "removed": cleanup.returncode == 0, "absent_after_cleanup": inspection.returncode != 0},
            sort_keys=True) + "\n")
        if cleanup.returncode != 0 or inspection.returncode == 0:
            raise RuntimeError("disposable PostgreSQL probe cleanup was not verified")


if __name__ == "__main__":
    raise SystemExit(main())
