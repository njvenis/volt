#!/usr/bin/env python3
"""Read-only full UVM/DefectDojo row and media inventory for G7 rollback proof."""
from __future__ import annotations
import argparse, hashlib, json, os
from pathlib import Path

def canon(value):
    if isinstance(value, bytes): return {"$bytes_sha256": hashlib.sha256(value).hexdigest(), "size": len(value)}
    if hasattr(value, "isoformat"): return value.isoformat()
    if hasattr(value, "as_tuple"): return str(value)
    if isinstance(value, dict): return {str(k):canon(v) for k,v in sorted(value.items(), key=lambda x:str(x[0]))}
    if isinstance(value, (list,tuple)): return [canon(v) for v in value]
    if value is None or isinstance(value,(str,int,float,bool)): return value
    return str(value)

def digest(value): return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()

def database_inventory(url):
    from sqlalchemy import MetaData, create_engine, select, text, inspect
    engine=create_engine(url, pool_pre_ping=True)
    result={}
    try:
        with engine.connect().execution_options(isolation_level="REPEATABLE READ") as conn:
            conn.execute(text("SET TRANSACTION READ ONLY"))
            meta=MetaData(); meta.reflect(bind=conn, schema="public")
            for table in sorted((t for t in meta.tables.values() if t.schema in (None,"public")),key=lambda t:t.name):
                columns=[{"name":c.name,"type":str(c.type),"nullable":c.nullable,"primary_key":c.primary_key,"default":str(getattr(c.server_default,"arg",c.server_default)) if c.server_default else None} for c in table.columns]
                rows=[]
                for row in conn.execute(select(table)).mappings():
                    item={k:canon(v) for k,v in row.items()}
                    pk=[item[c.name] for c in table.primary_key.columns]
                    record={"key":pk,"payload_sha256":digest(item)}
                    if table.name in {"g7_backup_state","g7_backup_host_records","g7_backup_settings_revisions","g7_backup_connector_quarantine","assessment_policy","g7_connectors"}:
                        record["payload"] = item
                    rows.append(record)
                rows.sort(key=lambda r:json.dumps(r["key"],sort_keys=True,separators=(",",":")))
                inspector=inspect(conn)
                constraints={"primary_key":inspector.get_pk_constraint(table.name,schema="public")["constrained_columns"],
                    "checks":sorted([x["sqltext"] for x in inspector.get_check_constraints(table.name,schema="public")]),
                    "unique":sorted([x["column_names"] for x in inspector.get_unique_constraints(table.name,schema="public")]),
                    "foreign_keys":canon(sorted([{k:v for k,v in x.items() if k != "name"} for x in inspector.get_foreign_keys(table.name,schema="public")],key=lambda x:json.dumps(x,sort_keys=True))),
                    "indexes":canon(sorted([{k:v for k,v in x.items() if k != "name"} for x in inspector.get_indexes(table.name,schema="public")],key=lambda x:json.dumps(x,sort_keys=True)))}
                result[table.name]={"columns":columns,"constraints":constraints,"schema_sha256":digest({"columns":columns,"constraints":constraints}),"rows":rows,"row_count":len(rows)}
    finally: engine.dispose()
    return result

def media_inventory(root):
    base=Path(root); out=[]
    if not base.exists(): return out
    for p in sorted(x for x in base.rglob("*") if x.is_file()):
        data=p.read_bytes(); out.append({"path":p.relative_to(base).as_posix(),"sha256":hashlib.sha256(data).hexdigest(),"size":len(data),"mode":p.stat().st_mode & 0o777})
    return out

def capture():
    from sqlalchemy.engine import URL
    secret=lambda name:Path("/run/secrets/"+name).read_text().strip()
    uvm=URL.create("postgresql+psycopg",username="uvm_app",password=secret("uvm_db_password"),host="127.0.0.1",port=5432,database="uvm")
    ce=URL.create("postgresql+psycopg",username="ce_app",password=secret("ce_db_password"),host="127.0.0.1",port=5432,database="defectdojo")
    return {"schema_version":1,"uvm":database_inventory(uvm),"ce":database_inventory(ce),"media":media_inventory("/app/media")}

def comparable(value):
    if isinstance(value, dict): return {k:comparable(v) for k,v in value.items() if k != "payload"}
    if isinstance(value, list): return [comparable(v) for v in value]
    return value


def compare(before,after,expected=None):
    # Default is strict equality. Only an independently replayed expectation can
    # admit an exact row payload or schema delta, never a table/key category.
    expected = before if expected is None else expected
    changes=[]; unknown=[]
    for database in ("uvm","ce"):
        left,right,wanted=before[database],after[database],expected[database]
        for name in sorted(set(left)|set(right)|set(wanted)):
            old,new,target=(comparable(x.get(name)) for x in (left,right,wanted))
            if old==new==target: continue
            old_rows={json.dumps(r["key"],separators=(",",":")):r["payload_sha256"] for r in (old or {}).get("rows",[])}
            new_rows={json.dumps(r["key"],separators=(",",":")):r["payload_sha256"] for r in (new or {}).get("rows",[])}
            changed=[{"key":json.loads(k),"before_payload_sha256":old_rows.get(k),"after_payload_sha256":new_rows.get(k)} for k in sorted(set(old_rows)|set(new_rows)) if old_rows.get(k)!=new_rows.get(k)]
            item={"database":database,"table":name,"before":old,"after":new,
                "expected":target,"changed_rows":changed,
                "schema_changed":(old or {}).get("schema_sha256")!=(new or {}).get("schema_sha256")}
            (changes if new==target else unknown).append(item)
    if before.get("media") != after.get("media"):
        unknown.append({"database":"media","table":"/app/media","before":before.get("media"),"after":after.get("media")})
    return {"allowed_deltas":changes,"unexpected_deltas":unknown,
      "product_mutation_count":sum(len(x.get("changed_rows",[])) for x in unknown),
      "control_mutation_count":sum(len(x.get("changed_rows",[])) for x in changes),
      "unexpected_inventory_change_count":len(unknown),"source_digest":"sha256:"+digest(before),"candidate_digest":"sha256:"+digest(after),
      "expectation_digest":"sha256:"+digest(expected),
      "delta_digest":"sha256:"+digest({"allowed":changes,"unexpected":unknown})}

def main():
    p=argparse.ArgumentParser(); p.add_argument("--output",required=True); p.add_argument("--compare",nargs=2); p.add_argument("--journal"); p.add_argument("--public-key"); p.add_argument("--expected-output")
    a=p.parse_args();
    if a.compare:
        from tools.g7_inventory_expectation import expected_inventory
        before=json.loads(Path(a.compare[0]).read_text())
        journal=json.loads(Path(a.journal).read_text())
        receipts=journal["submission_receipts"]
        expected=expected_inventory(before,receipts,Path(a.public_key))
        Path(a.expected_output).write_text(json.dumps(expected,sort_keys=True,separators=(",",":"))+"\n")
        result=compare(before,json.loads(Path(a.compare[1]).read_text()),expected)
        result["passed"]=result["unexpected_inventory_change_count"]==0
    else: result=capture()
    Path(a.output).write_text(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n")
    if result.get("passed") is False: return 2
    return 0
if __name__=="__main__": raise SystemExit(main())
