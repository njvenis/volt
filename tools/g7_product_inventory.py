#!/usr/bin/env python3
"""Read-only full UVM/DefectDojo row and media inventory for G7 rollback proof."""
from __future__ import annotations
import argparse, hashlib, json, os
from pathlib import Path

ALLOWED_UVM_TABLES = {
    "alembic_version", "g7_backup_settings_revisions", "g7_backup_state",
    "g7_backup_host_records", "g7_backup_connector_quarantine",
    "g7_backup_projection_evidence", "auth_identity_events",
    "g7_observer_host_reports", "g7_observer_status", "oidc_sync_state",
}
APPEND_ONLY_UVM_TABLES={"g7_backup_settings_revisions","g7_backup_host_records","g7_backup_connector_quarantine","g7_backup_projection_evidence","auth_identity_events","g7_observer_host_reports"}
UPDATE_KEYS={"g7_backup_state":{("g7-local",)},"g7_observer_status":{("g7-local",)},"oidc_sync_state":{("g7-synthetic",)}}

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
    from sqlalchemy import MetaData, create_engine, select, text
    engine=create_engine(url, pool_pre_ping=True)
    result={}
    try:
        with engine.connect().execution_options(isolation_level="REPEATABLE READ") as conn:
            conn.execute(text("SET TRANSACTION READ ONLY"))
            meta=MetaData(); meta.reflect(bind=conn, schema="public")
            for table in sorted((t for t in meta.tables.values() if t.schema in (None,"public")),key=lambda t:t.name):
                columns=[{"name":c.name,"type":str(c.type),"nullable":c.nullable,"primary_key":c.primary_key} for c in table.columns]
                rows=[]
                for row in conn.execute(select(table)).mappings():
                    item={k:canon(v) for k,v in row.items()}
                    pk=[item[c.name] for c in table.primary_key.columns]
                    rows.append({"key":pk,"payload_sha256":digest(item)})
                rows.sort(key=lambda r:json.dumps(r["key"],sort_keys=True,separators=(",",":")))
                result[table.name]={"columns":columns,"schema_sha256":digest(columns),"rows":rows,"row_count":len(rows)}
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

def compare(before,after):
    changes=[]; unknown=[]
    for database in ("uvm","ce"):
        left,right=before[database],after[database]
        for name in sorted(set(left)|set(right)):
            if left.get(name)==right.get(name): continue
            item={"database":database,"table":name,"before":left.get(name),"after":right.get(name)}
            old_rows={json.dumps(r["key"],sort_keys=True,separators=(",",":")):r["payload_sha256"] for r in (left.get(name) or {}).get("rows",[])}
            new_rows={json.dumps(r["key"],sort_keys=True,separators=(",",":")):r["payload_sha256"] for r in (right.get(name) or {}).get("rows",[])}
            changed=[{"key":json.loads(k),"before_payload_sha256":old_rows.get(k),"after_payload_sha256":new_rows.get(k)} for k in sorted(set(old_rows)|set(new_rows)) if old_rows.get(k)!=new_rows.get(k)]
            if database=="uvm" and name in ALLOWED_UVM_TABLES:
                item["changed_rows"]=changed
                item["schema_changed"]=(left.get(name) or {}).get("schema_sha256")!=(right.get(name) or {}).get("schema_sha256")
                if name=="alembic_version":
                    valid=changed==[{"key":["0058"],"before_payload_sha256":old_rows.get('["0058"]'),"after_payload_sha256":None},{"key":["0059"],"before_payload_sha256":None,"after_payload_sha256":new_rows.get('["0059"]')}]
                    if not valid: unknown.append(item); continue
                elif name in APPEND_ONLY_UVM_TABLES:
                    valid=all(old_rows.get(k)==new_rows.get(k) for k in old_rows) and all(old_rows.get(k) is None for k in new_rows if k not in old_rows)
                    if not valid: unknown.append(item); continue
                elif name in UPDATE_KEYS:
                    valid=(set(old_rows)==set(new_rows) and all(old_rows[k]==new_rows[k] or tuple(json.loads(k)) in UPDATE_KEYS[name] for k in old_rows))
                    if not valid: unknown.append(item); continue
                else: unknown.append(item); continue
                if not item["schema_changed"] and not changed: continue
                changes.append(item)
                continue
            item["changed_rows"]=changed
            if database=="media":
                old_media={x["path"]:x["sha256"] for x in before.get("media",[])}; new_media={x["path"]:x["sha256"] for x in after.get("media",[])}
                item["changed_rows"]=[{"path":k,"before_sha256":old_media.get(k),"after_sha256":new_media.get(k)} for k in sorted(set(old_media)|set(new_media)) if old_media.get(k)!=new_media.get(k)]
            unknown.append(item)
    if before.get("media") != after.get("media"):
        unknown.append({"database":"media","table":"/app/media","before":before.get("media"),"after":after.get("media")})
    changes.sort(key=lambda x:(x["database"],x["table"]))
    unknown.sort(key=lambda x:(x["database"],x["table"]))
    return {"allowed_deltas":changes,"unexpected_deltas":unknown,
      "product_mutation_count":sum(len(x.get("changed_rows",[])) for x in unknown),
      "control_mutation_count":sum(len(x.get("changed_rows",[])) for x in changes),
      "unexpected_inventory_change_count":len(unknown),"source_digest":"sha256:"+digest(before),"candidate_digest":"sha256:"+digest(after),
      "delta_digest":"sha256:"+digest({"allowed":changes,"unexpected":unknown})}

def main():
    p=argparse.ArgumentParser(); p.add_argument("--output",required=True); p.add_argument("--compare",nargs=2)
    a=p.parse_args();
    if a.compare:
        result=compare(json.loads(Path(a.compare[0]).read_text()),json.loads(Path(a.compare[1]).read_text()))
        result["passed"]=result["unexpected_inventory_change_count"]==0
    else: result=capture()
    Path(a.output).write_text(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n")
    if result.get("passed") is False: return 2
    return 0
if __name__=="__main__": raise SystemExit(main())
