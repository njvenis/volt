#!/usr/bin/env python3
"""Run the maintained producer against disposable PostgreSQL and byte-store copies.

Only run-owned containers/databases/files are modified. Baseline membership is
copied from the prior independent admission and is never regenerated from damage.
Raw database dumps and response bytes stay in the private run root, not evidence.
"""
from __future__ import annotations
import argparse
import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
PG = '/usr/lib/postgresql/18/bin/'
_CID_ROOT = None
_HELPERS = []
_ERROR_ROOT = None
_DIAGNOSTIC_SECRETS = []
_STAGE = "setup"
_NEXT_COPY_PORT = 18100


def run(command, *, data=None, code='copied_store_command_failed', stdout=None):
    result = subprocess.run(command, input=data, stdout=stdout or subprocess.PIPE,
        stderr=subprocess.PIPE, check=False)
    if result.returncode:
        # Keep only the first diagnostic line: subsequent DETAIL/CONTEXT may
        # contain source rows. Preserve the full original hash for identity.
        if _ERROR_ROOT is not None:
            first=result.stderr.splitlines()[:1]
            safe=first[0] if first else b''
            for value in _DIAGNOSTIC_SECRETS:
                if value:safe=safe.replace(value.encode(),b'[REDACTED]')
            (_ERROR_ROOT/'command-failure.json').write_text(json.dumps({
                'stage':_STAGE,'exit':result.returncode,'code':code,
                'stderr_sha256':hashlib.sha256(result.stderr).hexdigest(),
                'first_line_redacted':safe.decode(errors='replace')})+'\n')
        raise RuntimeError(code+':'+_STAGE)
    return result.stdout


def docker(*args, **kwargs):
    args=list(map(str,args)); cid_path=None
    if args and args[0]=='run' and '--rm' in args and _CID_ROOT is not None:
        cid_path=_CID_ROOT/('helper-'+secrets.token_hex(8)+'.cid')
        args[1:1]=['--cidfile',str(cid_path)]
    try:
        return run(['docker',*args],**kwargs)
    finally:
        if cid_path is not None and cid_path.exists():
            cid=cid_path.read_text().strip()
            present=subprocess.run(['docker','inspect',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
            _HELPERS.append({'container_id':cid,'absence_verified':not present})
            if present:raise RuntimeError('short_lived_helper_cleanup_failed')


def sql(container, database, statement):
    return docker('exec', '-i', container, PG+'psql', '-X', '-q', '-U', 'postgres',
        '-d', database, '-v', 'ON_ERROR_STOP=1', '-A', '-t', data=statement.encode())


def unused_port():
    # Docker's host forwarding service has its own port namespace. Avoid the
    # host ephemeral range and retry only an explicitly reported bind failure.
    global _NEXT_COPY_PORT
    for _ in range(100):
        port=_NEXT_COPY_PORT; _NEXT_COPY_PORT+=1
        if port>=18200:raise RuntimeError('copied_port_range_exhausted')
        with socket.socket() as sock:
            try:sock.bind(('127.0.0.1',port))
            except OSError:continue
            return port
    raise RuntimeError('copied_port_range_unavailable')


def atomic(path, raw, mode=0o644):
    temp = path.with_name('.copied-store-swap')
    temp.write_bytes(raw); temp.chmod(mode); os.replace(temp, path)


def request(origin, path, token, body=None):
    req = Request(origin+path, data=body, method='POST' if body is not None else 'GET',
        headers={'Authorization':'Bearer '+token, 'Content-Type':'application/json'})
    try:
        with urlopen(req, timeout=5) as response: return response.status, response.read()
    except HTTPError as exc: return exc.code, exc.read(4096)
    except (URLError, TimeoutError, OSError): return 0, b''


def main():
    global _CID_ROOT, _ERROR_ROOT, _STAGE
    parser=argparse.ArgumentParser()
    for name in ('run-root','source-container','anchor-container','image','evidence-dir',
                 'report-path','key-valid-from','key-valid-until','schema-head-digest'):
        parser.add_argument('--'+name, required=True)
    args=parser.parse_args(); root=Path(args.run_root); evidence=Path(args.evidence_dir)
    evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
    _ERROR_ROOT=evidence
    base_env=dict(line.split('=',1) for line in (root/'container.env').read_text().splitlines()
        if '=' in line and not line.startswith('#'))
    # Frozen copied identity state has an explicit test-only lease covering
    # this bounded matrix. Its stored heartbeat is preserved, never retimed.
    copied_oidc=json.loads(base_env['UVM_OIDC_CONFIG'])
    original_identity_lease=copied_oidc['heartbeat_max_age_seconds']
    copied_oidc['heartbeat_max_age_seconds']=900
    base_env['UVM_OIDC_CONFIG']=json.dumps(copied_oidc,separators=(',',':'))
    (evidence/'test-only-fixture-context.json').write_text(json.dumps({
        'normal_application':True,'startup_and_shutdown_hooks_disabled':True,
        'http_fence':'preservation GETs and read-only internal source snapshot POST only',
        'original_identity_lease_seconds':original_identity_lease,'copied_identity_lease_seconds':900,
        'stored_identity_heartbeat_modified':False,'report_and_source_check_times_retimed':False,
        'source_reader_grants':['SELECT public tables','INSERT assessment_sink_export_receipts'],
        'source_writer_grants':'separate copied-store-only scanner writer role; no HTTP writes',
        'external_scanner_or_provider_requests':False},indent=2)+'\n')
    run_id=root.name.rsplit('.',1)[-1]
    if not run_id.isalnum(): raise RuntimeError('invalid_owned_run_id')
    for container in (args.source_container,args.anchor_container):
        labels=json.loads(docker('inspect',container,'--format','{{json .Config.Labels}}'))
        if labels.get('uvm.g7.run-id') != run_id: raise RuntimeError('container_not_owned_by_run')
    prefix='g7_copy_'+run_id.lower()+'_'; role=prefix+'reader'; writer_role=prefix+'writer'
    dbs={name:prefix+name for name in ('base_source','base_sink','base_anchor','source','sink','anchor')}
    copy_root=root/'copied-preservation'; copy_root.mkdir(mode=0o700)
    _CID_ROOT=copy_root
    token=(root/'secrets/g7_preservation_source_token').read_text().strip()
    copy_password=secrets.token_hex(24)
    _DIAGNOSTIC_SECRETS.extend([token,copy_password,(root/"secrets/uvm_cursor_secret").read_text().strip()])
    host_trust=root/'host/preservation-trust'
    backup_trust=copy_root/'original-trust'; shutil.copytree(host_trust,backup_trust)
    original_report=Path(args.report_path).read_bytes()
    original_payload=json.loads(original_report)['payload']
    baseline_counts={item['class_id']:item['dto']['expected_records'] for item in original_payload['classes']}
    source_class='product.source_evidence'; audit_class='product.audit_history'; scanner_class='operational.scanner_collection'
    api_name='volt-g7-preservation-copy-'+run_id
    api_id=None; results=[]; cleanup=[]
    # Copy source and narrow runtime secrets with original UID/modes. No signing key is mounted.
    docker('cp','-a',args.source_container+':/opt/uvm/state/source-evidence',copy_root/'bytes-base')
    docker('cp','-a',args.source_container+':/run/uvm-g7-secrets',copy_root/'api-secrets')
    # docker cp crosses the daemon's ownership mapping. Normalize only the
    # private copied secrets for the fixture UID; never loosen their modes.
    docker('run','--rm','--network','none','--user','0:0','--label','uvm.g7.run-id='+run_id,
        '--tmpfs','/var/lib/postgresql/data','--tmpfs','/app/media','--tmpfs','/opt/uvm/state',
        '--mount',f'type=bind,src={copy_root/"api-secrets"},dst=/copied-secrets',
        '--mount',f'type=bind,src={root/"secrets/registry.json"},dst=/copied-registry.json,readonly',
        '--entrypoint','/bin/sh',args.image,'-c',
        'cp /copied-registry.json /copied-secrets/registry.json && chown -R 1800:1800 /copied-secrets && find /copied-secrets -type d -exec chmod 0700 {} + && find /copied-secrets -type f -exec chmod 0600 {} +')
    source_ports=json.loads(docker('inspect',args.source_container,'--format','{{json .NetworkSettings.Ports}}'))
    ui_origin='http://127.0.0.1:'+source_ports['8000/tcp'][0]['HostPort']
    anchor_ip=docker('inspect',args.anchor_container,'--format',
        '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}').decode().strip()
    sql(args.anchor_container,'postgres',f"CREATE ROLE {role} LOGIN PASSWORD '{copy_password}'; CREATE ROLE {writer_role} LOGIN PASSWORD '{copy_password}';")
    for kind, source_container, source_database in (
            ('source',args.source_container,'uvm'),('sink',args.anchor_container,'audit_sink'),
            ('anchor',args.anchor_container,'audit_anchor')):
        dump=copy_root/(kind+'.dump')
        with dump.open('wb') as out:
            docker('exec','-u','postgres',source_container,PG+'pg_dump','-U','postgres',
                '--format=custom','--no-owner','--no-privileges',source_database,stdout=out)
        dump.chmod(0o600)
        docker('exec',args.anchor_container,PG+'createdb','-U','postgres','--encoding=UTF8','--template=template0',dbs['base_'+kind])
        with dump.open('rb') as stream:
            result=subprocess.run(['docker','exec','-i',args.anchor_container,PG+'pg_restore',
                '-U','postgres','--no-owner','--no-privileges','-d',dbs['base_'+kind]],
                stdin=stream,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        if result.returncode: raise RuntimeError('copy_restore_failed')
    sql(args.anchor_container,dbs['base_source'],f'GRANT USAGE ON SCHEMA public TO {role}; GRANT SELECT ON ALL TABLES IN SCHEMA public TO {role}; GRANT INSERT ON assessment_sink_export_receipts TO {role};')
    sql(args.anchor_container,dbs['base_source'],f'GRANT USAGE ON SCHEMA public TO {writer_role}; GRANT SELECT ON ALL TABLES IN SCHEMA public TO {writer_role}; GRANT INSERT,UPDATE ON collection_schedules,expected_runs,expected_run_events,collection_runs,collection_request_reservations,run_attempts,run_pages,ingestion_evidence,assessment_audit_events TO {writer_role};')
    sql(args.anchor_container,dbs['base_sink'],'GRANT USAGE ON SCHEMA uvm_audit_export TO siem_exporter; GRANT SELECT,INSERT ON uvm_audit_export.events TO siem_exporter;')
    sql(args.anchor_container,dbs['base_anchor'],'GRANT USAGE ON SCHEMA uvm_audit_anchor TO anchor_signer,exporter_ro; GRANT SELECT,INSERT ON uvm_audit_anchor.inventory,uvm_audit_anchor.incidents TO anchor_signer; GRANT SELECT ON uvm_audit_anchor.inventory TO exporter_ro; GRANT SELECT,INSERT ON uvm_audit_anchor.incidents TO exporter_ro;')
    cases=[
        ('source_collection_lost',{source_class:'gap',scanner_class:'gap'},'source'),
        ('source_digest_metadata_changed',{source_class:'gap',scanner_class:'gap'},'source'),
        ('source_size_metadata_changed',{source_class:'gap'},'source-adapter-metadata-fault'),
        ('later_audit_append',{scanner_class:'gap'},'addition'),
        ('source_content_changed',{source_class:'gap',scanner_class:'gap'},'source'),
        ('reservation_changed',{scanner_class:'gap'},'source'),
        ('evidence_missing',{source_class:'gap',scanner_class:'gap'},'bytes'),
        ('evidence_changed',{source_class:'gap',scanner_class:'gap'},'bytes'),
        ('evidence_and_registration_changed',{source_class:'gap',scanner_class:'gap'},'bytes'),
        ('evidence_unavailable',{source_class:'failed',scanner_class:'failed'},'bytes'),
        ('sink_event_missing',{audit_class:'gap'},'sink'),
        ('sink_all_events_missing',{audit_class:'gap'},'sink'),
        ('sink_event_changed',{audit_class:'gap'},'sink'),
        ('source_audit_all_lost',{audit_class:'gap'},'source'),
        ('source_receipt_missing',{audit_class:'gap'},'source'),
        ('source_receipt_changed',{audit_class:'gap'},'source'),
        ('anchor_missing',{audit_class:'gap'},'anchor'),
        ('anchor_changed',{audit_class:'gap'},'anchor'),
        ('all_audit_stores_empty',{audit_class:'gap'},'all'),
        ('sink_unavailable',{audit_class:'failed'},'sink'),
        ('sink_timestamp_equivalent',{},'sink'),
        ('legitimate_source_addition',{},'addition'),
        ('post_admission_collection_lost',{source_class:'gap',scanner_class:'gap'},'source'),
        ('pending_first_receipt',{audit_class:'unknown'},'addition'),
        ('unexpected_sink_only',{audit_class:'gap'},'sink'),
    ]
    def stop_api():
        nonlocal api_id
        if api_id is None: return
        docker('rm','-f',api_id)
        if subprocess.run(['docker','inspect',api_id],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
            raise RuntimeError('copied_api_cleanup_failed')
        cleanup.append({'container_id':api_id,'absence_verified':True}); api_id=None
    try:
        for case, affected, _ in cases:
            expected_counts=dict(baseline_counts)
            if case=='legitimate_source_addition':
                for class_id,added in ((source_class,4),(audit_class,16),(scanner_class,17)):expected_counts[class_id]+=added
            elif case=='pending_first_receipt':
                expected_counts[audit_class]+=2;expected_counts[scanner_class]+=4
            _STAGE=case+':stop_api'
            stop_api()
            for kind in ('source','sink','anchor'):
                _STAGE=case+':restore:'+kind
                sql(args.anchor_container,'postgres',f'DROP DATABASE IF EXISTS {dbs[kind]} WITH (FORCE); CREATE DATABASE {dbs[kind]} TEMPLATE {dbs["base_"+kind]};')
            _STAGE=case+':copy_bytes'
            trust=copy_root/('trust-'+case); shutil.copytree(backup_trust,trust)
            # Preserve source bytes exactly, then mutate only the run-owned copy.
            bytes_copy=copy_root/('bytes-'+case)
            docker('run','--rm','--network','none','--user','0:0','--label','uvm.g7.run-id='+run_id,
                '--tmpfs','/var/lib/postgresql/data','--tmpfs','/app/media','--tmpfs','/opt/uvm/state',
                '--mount',f'type=bind,src={copy_root},dst=/owned',
                '--entrypoint','/bin/sh',args.image,'-c',
                'cp -a /owned/bytes-base /owned/'+bytes_copy.name+' && chown -R 1800:1800 /owned/'+bytes_copy.name)
            metadata=docker('run','--rm','--network','none','--user','0:0','--label','uvm.g7.run-id='+run_id,
                '--tmpfs','/var/lib/postgresql/data','--tmpfs','/app/media','--tmpfs','/opt/uvm/state',
                '--mount',f'type=bind,src={bytes_copy},dst=/bytes,readonly',
                '--entrypoint','/opt/uvm/venv/bin/python',args.image,'-c',
                "from pathlib import Path; import json,stat,hashlib; print(json.dumps([{'name':p.name,'uid':p.stat().st_uid,'gid':p.stat().st_gid,'mode':oct(stat.S_IMODE(p.stat().st_mode)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None} for p in [Path('/bytes'),*Path('/bytes').iterdir()]]))")
            (evidence/(case+'-copied-byte-bindings.json')).write_bytes(metadata)
            _STAGE=case+':mutate'
            if case in {'source_collection_lost','post_admission_collection_lost'}:
                sql(args.anchor_container,dbs['source'],'DELETE FROM ingestion_evidence; DELETE FROM run_pages; DELETE FROM run_attempts; DELETE FROM collection_request_reservations; DELETE FROM expected_run_events; DELETE FROM collection_runs;')
            elif case=='source_content_changed':
                sql(args.anchor_container,dbs['source'],"UPDATE collection_runs SET provenance_snapshot=jsonb_set(provenance_snapshot::jsonb,'{observations}',COALESCE((SELECT jsonb_agg(jsonb_set(item,'{source_rating}','\"changed-copy\"'::jsonb)) FROM jsonb_array_elements((provenance_snapshot::jsonb)->'observations') item),'[]'::jsonb));")
            elif case=='source_digest_metadata_changed':
                sql(args.anchor_container,dbs['source'],"UPDATE collection_runs SET provenance_snapshot=jsonb_set(provenance_snapshot::jsonb,'{observations}',COALESCE((SELECT jsonb_agg(jsonb_set(item,'{raw_evidence_sha256}',to_jsonb(repeat('c',64)))) FROM jsonb_array_elements((provenance_snapshot::jsonb)->'observations') item),'[]'::jsonb));")
            elif case=='reservation_changed':
                sql(args.anchor_container,dbs['source'],"UPDATE collection_request_reservations SET request_identity_sha256=repeat('f',64);")
            elif case in {'evidence_missing','evidence_changed','evidence_and_registration_changed','evidence_unavailable'}:
                action={
                    'evidence_missing':"[p.unlink() for p in Path('/bytes').iterdir() if p.is_file()]",
                    'evidence_changed':"[(p.chmod(0o600),p.write_bytes(b'changed-copy-response')) for p in Path('/bytes').iterdir() if p.is_file()]",
                    'evidence_and_registration_changed':"[(p.chmod(0o600),p.write_bytes(b'changed-copy-response')) for p in Path('/bytes').iterdir() if p.is_file()]",
                    'evidence_unavailable':"Path('/bytes').chmod(0o000)",}[case]
                docker('run','--rm','--network','none','--user','0:0','--label','uvm.g7.run-id='+run_id,
                '--tmpfs','/var/lib/postgresql/data','--tmpfs','/app/media','--tmpfs','/opt/uvm/state','--mount',f'type=bind,src={bytes_copy},dst=/bytes',
                    '--entrypoint','/opt/uvm/venv/bin/python',args.image,'-c','from pathlib import Path; '+action)
                if case=='evidence_and_registration_changed':
                    digest=hashlib.sha256(b'changed-copy-response').hexdigest()
                    sql(args.anchor_container,dbs['source'],f"UPDATE ingestion_evidence SET sha256='{digest}',byte_size={len(b'changed-copy-response')};")
            elif case=='sink_event_missing': sql(args.anchor_container,dbs['sink'],'DELETE FROM uvm_audit_export.events WHERE event_id=(SELECT event_id FROM uvm_audit_export.events ORDER BY event_id LIMIT 1);')
            elif case=='sink_all_events_missing': sql(args.anchor_container,dbs['sink'],'DELETE FROM uvm_audit_export.events;')
            elif case=='sink_event_changed': sql(args.anchor_container,dbs['sink'],"UPDATE uvm_audit_export.events SET payload=jsonb_set(payload,'{rationale}','\"changed-copy\"'::jsonb) WHERE event_id=(SELECT event_id FROM uvm_audit_export.events ORDER BY event_id LIMIT 1);")
            elif case in {'source_audit_all_lost','all_audit_stores_empty'}:
                sql(args.anchor_container,dbs['source'],'TRUNCATE assessment_audit_events CASCADE;')
                if case=='all_audit_stores_empty':
                    sql(args.anchor_container,dbs['sink'],'DELETE FROM uvm_audit_export.events;')
                    sql(args.anchor_container,dbs['anchor'],'DELETE FROM uvm_audit_anchor.inventory;')
            elif case=='source_receipt_missing': sql(args.anchor_container,dbs['source'],'DELETE FROM assessment_sink_export_receipts WHERE event_id=(SELECT event_id FROM assessment_sink_export_receipts ORDER BY event_id LIMIT 1);')
            elif case=='source_receipt_changed': sql(args.anchor_container,dbs['source'],"UPDATE assessment_sink_export_receipts SET sink_receipt='changed-copy-receipt' WHERE event_id=(SELECT event_id FROM assessment_sink_export_receipts ORDER BY event_id LIMIT 1);")
            elif case=='anchor_missing': sql(args.anchor_container,dbs['anchor'],'DELETE FROM uvm_audit_anchor.inventory WHERE event_id=(SELECT event_id FROM uvm_audit_anchor.inventory ORDER BY event_id LIMIT 1);')
            elif case=='anchor_changed': sql(args.anchor_container,dbs['anchor'],"UPDATE uvm_audit_anchor.inventory SET affected_scope='changed-copy-scope' WHERE event_id=(SELECT event_id FROM uvm_audit_anchor.inventory ORDER BY event_id LIMIT 1);")
            if case=='sink_timestamp_equivalent':
                sql(args.anchor_container,dbs['sink'],"UPDATE uvm_audit_export.events SET payload=jsonb_set(jsonb_set(payload::jsonb,'{occurred_at}',to_jsonb(replace(payload->>'occurred_at','+00:00','Z'))),'{received_at}',to_jsonb(replace(payload->>'received_at','+00:00','Z')));")
            if case=='unexpected_sink_only':
                sql(args.anchor_container,dbs['sink'],"INSERT INTO uvm_audit_export.events(event_id,payload,committed_at) SELECT '00000000-0000-4000-8000-000000000099'::uuid,jsonb_set(jsonb_set(payload::jsonb,'{event_id}','\"00000000-0000-4000-8000-000000000099\"'::jsonb),'{event_sequence}',to_jsonb((SELECT max((payload->>'event_sequence')::bigint) FROM uvm_audit_export.events))),clock_timestamp() FROM uvm_audit_export.events ORDER BY event_id LIMIT 1;")
            if case in {'legitimate_source_addition','pending_first_receipt'}:
                _STAGE=case+':actual_scanner_writer'
                writer_env={**base_env,'UVM_DB_URL':f'postgresql+psycopg://{writer_role}:{copy_password}@{anchor_ip}:5432/{dbs["source"]}'}
                writer_env_file=copy_root/'writer.env';writer_env_file.write_text('\n'.join(k+'='+v for k,v in writer_env.items())+'\n');writer_env_file.chmod(0o600)
                written=docker('run','--rm','--user','1800:1800','--label','uvm.g7.run-id='+run_id,
                    '--env-file',writer_env_file,'--tmpfs','/var/lib/postgresql/data','--tmpfs','/app/media','--tmpfs','/opt/uvm/state:uid=1800,gid=1800,mode=0700',
                    '--mount',f'type=bind,src={bytes_copy},dst=/opt/uvm/state/source-evidence',
                    '--mount',f'type=bind,src={ROOT/"tools/g7_preservation_addition_fixture.py"},dst=/fixture/addition.py,readonly',
                    '--mount',f'type=bind,src={ROOT/"tools/g7_preservation_seed_source.py"},dst=/fixture/seed.py,readonly',
                    '--entrypoint','/opt/uvm/venv/bin/python',args.image,'/fixture/addition.py',
                    'complete' if case=='legitimate_source_addition' else 'pending')
                (evidence/(case+'-actual-writer.json')).write_bytes(written)
                committed=json.loads(written)
                if case=='legitimate_source_addition' and (committed['revision'],committed['observation_count'],committed['evidence_count'])!=(4,1,1):
                    raise RuntimeError('completed_writer_shape_changed')
            reports=copy_root/('reports-'+case); reports.mkdir(mode=0o755); reports.chmod(0o755)
            port=unused_port(); env={**base_env,'UVM_DB_URL':f'postgresql+psycopg://{role}:{copy_password}@{anchor_ip}:5432/{dbs["source"]}',
                'UVM_API_CURSOR_SECRET':(root/'secrets/uvm_cursor_secret').read_text().strip(),
                'UVM_G7_PRESERVATION_TRUST_DIR':'/trust',
                'UVM_G7_PRESERVATION_PUBLIC_KEY_FILE':'/trust/public.pem','UVM_G7_PRESERVATION_REPORT_DIR':'/reports',
                'UVM_UI_ROOT':'/opt/uvm/ui','PYTHONDONTWRITEBYTECODE':'1',
                'UVM_OBSERVER_DEPLOYMENT_REGISTRY_FILE':'/run/uvm-g7-secrets/registry.json'}
            env_file=copy_root/'api.env'; env_file.write_text('\n'.join(k+'='+v for k,v in env.items())+'\n'); env_file.chmod(0o600)
            _STAGE=case+':launch_api'
            api_command=['docker','run','-d','--name',api_name,'--label','uvm.g7.run-id='+run_id,
                '--user','1800:1800','--env-file',env_file,'-p',f'127.0.0.1:{port}:8000',
                '--tmpfs','/var/lib/postgresql/data','--tmpfs','/app/media','--tmpfs','/opt/uvm/state:uid=1800,gid=1800,mode=0700',
                '--mount',f'type=bind,src={trust},dst=/trust,readonly',
                '--mount',f'type=bind,src={reports},dst=/reports,readonly',
                '--mount',f'type=bind,src={bytes_copy},dst=/opt/uvm/state/source-evidence,readonly',
                '--mount',f'type=bind,src={copy_root/"api-secrets"},dst=/run/uvm-g7-secrets,readonly',
                '--entrypoint','/opt/uvm/venv/bin/python',args.image,'-c',
                ("from uvm.operations import preservation_source as source\n"
                 "native_member=source._member\n"
                 "def metadata_fault(*args,**kwargs):\n"
                 "    member=native_member(*args,**kwargs)\n"
                 "    if args[0]=='product.source_evidence' and member['record_kind']=='observation' and member['byte_size'] is not None: member['byte_size']+=1\n"
                 "    return member\n"
                 "source._member=metadata_fault\n" if case=='source_size_metadata_changed' else "") +
                "from uvm.api.app import app\n"
                "app.router.on_startup.clear(); app.router.on_shutdown.clear()\n"
                "async def fenced(scope, receive, send):\n"
                "    path=scope.get('path',''); method=scope.get('method','')\n"
                "    allowed=(method=='GET' and (path=='/openapi.json' or path.startswith('/api/v1/operations/preservation'))) or (method=='POST' and path=='/internal/g7/preservation/source-snapshot')\n"
                "    if scope['type']=='http' and not allowed:\n"
                "        await send({'type':'http.response.start','status':404,'headers':[]})\n"
                "        await send({'type':'http.response.body','body':b''}); return\n"
                "    await app(scope,receive,send)\n"
                "import uvicorn; uvicorn.run(fenced,host='0.0.0.0',port=8000,log_level='warning',lifespan='off')"]
            launches=[]
            for launch_attempt in range(5):
                api_command[api_command.index('-p')+1]=f'127.0.0.1:{port}:8000'
                launched=subprocess.run(list(map(str,api_command)),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                entry={'port':port,'exit':launched.returncode,
                    'stderr_sha256':hashlib.sha256(launched.stderr).hexdigest()}
                launches.append(entry)
                launch_diagnostics=launched.stderr
                for value in _DIAGNOSTIC_SECRETS:
                    if value:launch_diagnostics=launch_diagnostics.replace(value.encode(),b'[REDACTED]')
                (evidence/(case+'-api-launch-'+str(launch_attempt)+'-redacted.stderr')).write_bytes(launch_diagnostics)
                entry['redacted_stderr_sha256']=hashlib.sha256(launch_diagnostics).hexdigest()
                if launched.returncode==0:
                    api_id=launched.stdout.decode().strip()
                    break
                # Docker may create the container before its forwarding service
                # rejects Start. Resolve only this exact name and verify its label.
                failed=subprocess.run(['docker','inspect',api_name],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
                if failed.returncode==0:
                    identity=json.loads(failed.stdout)[0]
                    if identity['Config']['Labels'].get('uvm.g7.run-id')!=run_id:
                        raise RuntimeError('copied_failed_create_not_owned')
                    api_id=identity['Id'];entry['failed_container_id']=api_id
                    stop_api();entry['failed_create_absence_verified']=True
                (evidence/(case+'-api-launches.json')).write_text(json.dumps(launches,indent=2)+'\n')
                if not any(message in launched.stderr for message in (
                        b'ports are not available',b'address already in use',b'port is already allocated')):
                    raise RuntimeError('copied_api_launch_failed:'+case)
                port=unused_port()
            else:raise RuntimeError('copied_api_port_forwarding_unavailable:'+case)
            (evidence/(case+'-api-launches.json')).write_text(json.dumps(launches,indent=2)+'\n')
            origin=f'http://127.0.0.1:{port}'
            statuses=[]
            for _ in range(100):
                status,_=request(origin,'/openapi.json',token);statuses.append(status)
                if status==200: break
                time.sleep(.1)
            else:
                log=subprocess.run(['docker','logs',api_id],stdout=subprocess.PIPE,stderr=subprocess.STDOUT).stdout
                original_hash=hashlib.sha256(log).hexdigest()
                secret_values=[token,copy_password,env['UVM_API_CURSOR_SECRET']]
                for principal in json.loads(base_env.get('UVM_API_PRINCIPALS','{}')).values():
                    if isinstance(principal,dict) and isinstance(principal.get('token'),str):secret_values.append(principal['token'])
                for value in secret_values:
                    if value:log=log.replace(value.encode(),b'[REDACTED]')
                (evidence/(case+'-api-startup-redacted.log')).write_bytes(log)
                (evidence/(case+'-api-startup.json')).write_text(json.dumps({'statuses':statuses,
                    'original_log_sha256':original_hash,'redacted_log_sha256':hashlib.sha256(log).hexdigest()})+'\n')
                raise RuntimeError('copied_api_startup_failed:'+case+':'+str(status))
            protected_reads=[]
            for evidence_id in sorted({m['evidence_id'] for entry in original_payload['classes']
                    for m in entry['members'] if m.get('evidence_id')}):
                status,raw=request(origin,'/api/v1/operations/preservation/evidence/'+evidence_id,token)
                error_code=None
                if status!=200:
                    try:
                        error=json.loads(raw);detail=error.get('detail',error.get('error',error))
                        error_code=detail.get('code') if isinstance(detail,dict) else None
                    except ValueError:pass
                protected_reads.append({'evidence_id':evidence_id,'status':status,'error_code':error_code,
                    'response_sha256':hashlib.sha256(raw).hexdigest(),'response_size':len(raw)})
            (evidence/(case+'-protected-byte-reads.json')).write_text(json.dumps(protected_reads,indent=2)+'\n')
            audit_file=evidence/(case+'-audit-state.json')
            export_env={
                'G7_DEPLOYMENT_AUDIT_TOKEN':token,'G7_DEPLOYMENT_AUDIT_DATABASE_URL':env['UVM_DB_URL'],
                'G7_AUDIT_SOURCE_FAMILY':'local','G7_AUDIT_SOURCE_ACCOUNT':'g7-local','G7_AUDIT_SCOPE_KEY':'all',
                'G7_AUDIT_DEPLOYMENT_ID':'g7-local',
                'G7_AUDIT_ANCHOR_DSN':f'postgresql://exporter_ro:{(root/"host/exporter-ro-password").read_text().strip()}@{anchor_ip}:5432/{dbs["anchor"]}',
                'G7_SIEM_DSN':f'postgresql://siem_exporter:{(root/"host/siem-exporter-password").read_text().strip()}@{anchor_ip}:5432/{dbs["sink"]}',
                'G7_AUDIT_ANCHOR_SIGNER_DSN':f'postgresql://anchor_signer:{(root/"host/anchor-signer-password").read_text().strip()}@{anchor_ip}:5432/{dbs["anchor"]}'}
            if case=='later_audit_append':export_env['G7_WATERMARK_WRITER_DATABASE_URL']=f'postgresql+psycopg://{writer_role}:{copy_password}@{anchor_ip}:5432/{dbs["source"]}'
            if case=='sink_unavailable': export_env['G7_SIEM_DSN']='postgresql://unavailable:unavailable@127.0.0.1:9/unavailable?connect_timeout=2'
            export_env_file=copy_root/'export.env';export_env_file.write_text('\n'.join(k+'='+v for k,v in export_env.items())+'\n');export_env_file.chmod(0o600)
            if case in {'legitimate_source_addition','sink_timestamp_equivalent'}:
                for operation in (('siem-export','anchor-history') if case=='legitimate_source_addition' else ('siem-export',)):
                    _STAGE=case+':'+operation
                    completed=docker('exec','--env-file',export_env_file,api_id,'/opt/uvm/venv/bin/python',
                        '/opt/uvm/app/tools/g7_container_audit_export.py',operation,'--limit','5000')
                    (evidence/(case+'-'+operation+'.json')).write_bytes(completed)
            elif case=='pending_first_receipt':
                _STAGE=case+':actual_export_before_ack_failure'
                docker('cp',ROOT/'tools/g7_preservation_addition_fixture.py',api_id+':/tmp/addition.py')
                completed=docker('exec','--env-file',export_env_file,api_id,'/opt/uvm/venv/bin/python','/tmp/addition.py','pending-export')
                (evidence/(case+'-actual-export.json')).write_bytes(completed)
            command=['docker','exec','--env-file',str(export_env_file),api_id,
                '/opt/uvm/venv/bin/python','/opt/uvm/app/tools/g7_container_audit_export.py','audit-state','--limit','5000']
            if case in {'legitimate_source_addition','pending_first_receipt'}:command.append('--admit-new-members')
            if case=='later_audit_append':
                docker('cp',ROOT/'tools/g7_preservation_addition_fixture.py',api_id+':/tmp/addition.py')
                for rejected_mode in ('watermark-authority-change','watermark-context-change'):
                    rejected=subprocess.run(['docker','exec','--env-file',str(export_env_file),api_id,
                        '/opt/uvm/venv/bin/python','/tmp/addition.py',rejected_mode],capture_output=True)
                    safe=rejected.stderr
                    for value in _DIAGNOSTIC_SECRETS+[export_env['G7_WATERMARK_WRITER_DATABASE_URL']]:
                        if value:safe=safe.replace(value.encode(),b'[REDACTED]')
                    (evidence/(rejected_mode+'-redacted.stderr')).write_bytes(safe)
                    (evidence/(rejected_mode+'-exit.json')).write_text(json.dumps({'exit':rejected.returncode,'stdout_bytes':len(rejected.stdout),'original_stderr_sha256':hashlib.sha256(rejected.stderr).hexdigest(),'redacted_stderr_sha256':hashlib.sha256(safe).hexdigest()})+'\n')
                    if rejected.returncode==0 or rejected.stdout or b'PermissionError' not in rejected.stderr:raise RuntimeError('watermark_context_change_did_not_reject:'+rejected_mode)
                command=['docker','exec','--env-file',str(export_env_file),api_id,
                    '/opt/uvm/venv/bin/python','/tmp/addition.py','watermark-consumer']
            outcome=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            audit_file.write_bytes(outcome.stdout);audit_file.chmod(0o600)
            diagnostics=outcome.stderr
            original_stderr_hash=hashlib.sha256(diagnostics).hexdigest()
            for value in [token,copy_password,env['UVM_API_CURSOR_SECRET'],*[v for k,v in export_env.items() if any(t in k for t in ('TOKEN','DATABASE_URL','DSN'))]]:
                if value:diagnostics=diagnostics.replace(value.encode(),b'[REDACTED]')
            (evidence/(case+'-audit-state-redacted.stderr')).write_bytes(diagnostics)
            (evidence/(case+'-audit-state-exit.json')).write_text(json.dumps({
                'exit':outcome.returncode,'original_stderr_sha256':original_stderr_hash,
                'redacted_stderr_sha256':hashlib.sha256(diagnostics).hexdigest()})+'\n')
            if case=='sink_unavailable':
                if outcome.returncode==0 or outcome.stdout:raise RuntimeError('sink_outage_did_not_fail_closed')
            elif outcome.returncode: raise RuntimeError('copied_audit_reconciliation_failed:'+case)
            if case in {'source_digest_metadata_changed','source_size_metadata_changed'}:
                body=json.dumps({'schema_version':1,'scope':{'source_family':'local','source_account_id':'g7-local','scope_key':'all'},'class_ids':[source_class,audit_class,scanner_class]}).encode()
                status,raw=request(origin,'/internal/g7/preservation/source-snapshot',token,body)
                if status!=200:raise RuntimeError('metadata_source_snapshot_failed')
                (evidence/(case+'-actual-source-snapshot.json')).write_bytes(raw)
                (evidence/(case+'-fault-boundary.json')).write_text(json.dumps({'source_registration_and_bytes_unchanged':True,'fault':'copied provenance raw digest' if case=='source_digest_metadata_changed' else 'test-only source adapter byte_size output; native record hash and registration unchanged','signed_report_mutated':False})+'\n')
            capture=[str(ROOT/'.venv/bin/python'),str(ROOT/'tools/g7_preservation_inventory.py'),
                '--origin',origin,'--token-file',str(root/'secrets/g7_preservation_source_token'),
                '--signing-key-file',str(root/'host/ed25519.pem'),'--trust-dir',str(trust),
                '--report-dir',str(reports),'--key-id','g7-preservation-fixture','--deployment-id','g7-local',
                '--recovery-epoch','1','--storage-generation',base_env['UVM_G7_STORAGE_GENERATION'],
                '--freshness-seconds','900','--volume-set-digest',base_env['UVM_G7_VOLUME_SET_DIGEST'],'--schema-head-digest',args.schema_head_digest,
                '--key-valid-from',args.key_valid_from,'--key-valid-until',args.key_valid_until,
                '--metadata-output',str(evidence/(case+'-source-metadata.json')),
                '--environment','local-copied-postgresql-stores','--source-family','local','--source-account-id','g7-local','--scope-key','all']
            capture += ['--audit-state-failure-reason','sink_unavailable'] if case=='sink_unavailable' else ['--audit-state-file',str(audit_file)]
            if case in {'legitimate_source_addition','pending_first_receipt'}:capture.append('--admit-new-members')
            result=subprocess.run(capture,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            (evidence/(case+'-producer.stdout')).write_bytes(result.stdout)
            (evidence/(case+'-producer.stderr')).write_bytes(result.stderr)
            if result.returncode:raise RuntimeError('copied_producer_failed:'+case)
            report_file=next(reports.glob('*.json'));document=json.loads(report_file.read_bytes());payload=document['payload']
            classes={item['class_id']:item['dto'] for item in payload['classes']}
            shutil.copy2(report_file,evidence/(case+'-signed-report.json'))
            shutil.copytree(trust,evidence/(case+'-trust'))
            for class_id in (source_class,audit_class,scanner_class):
                expected=affected.get(class_id,'verified')
                if classes[class_id]['state'] != expected:raise RuntimeError('copied_state_mismatch:'+case+':'+class_id+':'+classes[class_id]['state'])
                if expected=='failed':
                    if classes[class_id]['expected_records'] is not None:raise RuntimeError('outage_exposed_partial_counts')
                elif classes[class_id]['expected_records'] != expected_counts[class_id]:raise RuntimeError('expected_membership_shrank:'+case)
            if case in {'evidence_missing','evidence_changed','evidence_and_registration_changed'}:
                selected=next(m for entry in original_payload['classes'] for m in entry['members'] if m.get('evidence_id'))
                status,raw=request(origin,'/api/v1/operations/preservation/evidence/'+selected['evidence_id'],token)
                if status != 409:raise RuntimeError('damaged_bytes_not_denied:'+case)
                if b'changed-copy-response' in raw:raise RuntimeError('damaged_byte_response_disclosed')
            expected_states={key:affected.get(key,'verified') for key in (source_class,audit_class,scanner_class)}
            expected={'case':case, 'states':expected_states,
                'counts':{key:expected_counts[key] for key,value in expected_states.items() if value!='failed'},
                'nullCountClasses':[key for key,value in expected_states.items() if value=='failed']}
            for key,value in expected_states.items():
                if value=='gap': expected['recordClass']=key; break
            if case=='pending_first_receipt':expected.update(recordClass=audit_class,paginateAll=True,renderedPending=True,uiOrigin=ui_origin,reportPath=str(report_file),metadataPath=str(evidence/(case+'-source-metadata.json')),browserEvidence=str(evidence/'pending-rendered-browser'))
            if case in {'source_digest_metadata_changed','source_size_metadata_changed'}:expected.update(recordClass=source_class,recordState='changed',recordReason='evidence_changed',rawHashesEqual=True,noByteChangedReason=True)
            if case=='pending_first_receipt':expected['auditCopy']={'pending_receipts':1,'missing_receipts':0,'changed_receipts':0,'unexpected_receipts':0};expected['reasons']={audit_class:'source_checkpoint_missing'}
            if case=='unexpected_sink_only':expected['auditCopy']={'unexpected_events':1,'pending_receipts':0};expected['recordClass']=audit_class;expected['recordState']='unexpected';expected['recordReason']='unexpected_member'
            expected_path=evidence/(case+'-public-expect.json');expected_path.write_text(json.dumps(expected)+'\n')
            browser_env=dict(os.environ)
            browser=subprocess.run(['node',str(ROOT/'tools/g7_preservation_report_failure_matrix.mjs'),
                '--origin',origin,'--storage-state',str(root/'host/preservation-session.json'),
                '--expect',str(expected_path),'--output',str(evidence/(case+'-public.json'))],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=browser_env)
            (evidence/(case+'-public.stdout')).write_bytes(browser.stdout)
            (evidence/(case+'-public.stderr')).write_bytes(browser.stderr)
            if browser.returncode:raise RuntimeError('copied_public_projection_failed:'+case)
            results.append({'case':case,'producer_exit':0,'audit_state_exit':outcome.returncode,
                'classes':{key:{'state':dto['state'],'expected_records':dto['expected_records'],
                    'missing_records':dto['missing_records'],'changed_records':dto['changed_records'],
                    'unreadable_records':dto['unreadable_records'],'unexpected_records':dto['unexpected_records']}
                    for key,dto in classes.items()},'expectation_source':'independent-prior-signed-inventory',
                'environment':'local-copied-postgresql-and-byte-stores'})
            (evidence/'copied-store-results.json').write_text(json.dumps(results,indent=2)+'\n')
            if case=='legitimate_source_addition':
                # Advance templates only after actual writer/exporter/observer,
                # explicit signed additive admission and public validation pass.
                stop_api()
                for kind in ('source','sink','anchor'):
                    sql(args.anchor_container,'postgres',f'DROP DATABASE {dbs["base_"+kind]} WITH (FORCE); CREATE DATABASE {dbs["base_"+kind]} TEMPLATE {dbs[kind]};')
                backup_trust=copy_root/'admitted-trust';shutil.copytree(trust,backup_trust)
                docker('run','--rm','--network','none','--user','0:0','--label','uvm.g7.run-id='+run_id,
                    '--tmpfs','/var/lib/postgresql/data','--tmpfs','/app/media','--tmpfs','/opt/uvm/state',
                    '--mount',f'type=bind,src={copy_root},dst=/owned','--entrypoint','/bin/sh',args.image,
                    '-c','rm -rf /owned/bytes-base && cp -a /owned/'+bytes_copy.name+' /owned/bytes-base')
                baseline_counts=expected_counts;original_payload=payload
    finally:
        stop_api()
        for database in dbs.values():
            sql(args.anchor_container,'postgres',f'DROP DATABASE IF EXISTS {database} WITH (FORCE);')
        sql(args.anchor_container,'postgres',f'DROP ROLE IF EXISTS {role}; DROP ROLE IF EXISTS {writer_role};')
        role_count=sql(args.anchor_container,'postgres',f"SELECT count(*) FROM pg_roles WHERE rolname IN ('{role}','{writer_role}');").decode().strip()
        if role_count!='0':raise RuntimeError('copied_roles_not_cleaned')
        count=sql(args.anchor_container,'postgres',"SELECT count(*) FROM pg_database WHERE datname IN ("+
            ','.join("'"+name+"'" for name in dbs.values())+");").decode().strip()
        if count!='0':raise RuntimeError('copied_databases_not_cleaned')
        docker('run','--rm','--network','none','--user','0:0','--label','uvm.g7.run-id='+run_id,
            '--tmpfs','/var/lib/postgresql/data','--tmpfs','/app/media','--tmpfs','/opt/uvm/state',
            '--mount',f'type=bind,src={copy_root},dst=/owned','--entrypoint','/bin/sh',args.image,
            '-c',f'chown -R {os.getuid()}:{os.getgid()} /owned && chmod -R u+rwX /owned')
        (evidence/'copied-store-cleanup.json').write_text(json.dumps({'containers':cleanup,'short_lived_helpers':_HELPERS,
            'database_names':list(dbs.values()),'database_absence_verified':True,'role_names':[role,writer_role],'role_absence_verified':True},indent=2)+'\n')
    print(json.dumps({'cases':len(results),'cleanup_verified':True}))

if __name__=='__main__':
    try: main()
    except RuntimeError as exc: raise SystemExit(str(exc))
