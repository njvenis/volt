#!/usr/bin/env python3
"""Run the real host-send/app-down/recovery/public-catchup G7 journey."""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, signal, socket, subprocess, sys, time, urllib.error, urllib.request, uuid
from datetime import datetime, timezone

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools import g7_operational_alert_sender as sender

def capture(path, data):
    p=pathlib.Path(path); p.parent.mkdir(parents=True,exist_ok=True,mode=0o700); p.write_text(data); os.chmod(p,0o600)
def wait_for(label, predicate, deadline, delay=.5):
    while time.monotonic()<deadline:
        result=predicate()
        if result: return result
        time.sleep(delay)
    raise RuntimeError('timeout:'+label)
def read_records(path):
    return sender.Journal(path)._read()['records']
def docker(args, *, input_data=None):
    return subprocess.run(['docker',*args],input=input_data,text=True,capture_output=True,check=True).stdout.strip()
def complete_local_audit_anchor(container, run_id, root, evidence):
    """Export actual setup audit events through the disposable signed sink path."""
    anchor_name=f"volt-g7-operational-anchor-{run_id}"
    address=docker(['inspect',anchor_name,'--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'])
    if not __import__('re').fullmatch(r"[0-9.]+",address): raise RuntimeError('disposable anchor address is invalid')
    host=pathlib.Path(root)/'host'; secrets=pathlib.Path(root)/'secrets'
    def secret(name): return (host/name).read_text().strip()
    token=(secrets/'g7_preservation_source_token').read_text().strip()
    siem=secret('siem-exporter-password'); exporter=secret('exporter-ro-password'); signer=secret('anchor-signer-password')
    envs={
        'G7_DEPLOYMENT_AUDIT_TOKEN':token,'G7_AUDIT_SOURCE_FAMILY':'local',
        'G7_AUDIT_SOURCE_ACCOUNT':'g7-local','G7_AUDIT_SCOPE_KEY':'all',
        'G7_AUDIT_AUTH_ORIGIN':'http://127.0.0.1:8000','G7_AUDIT_DEPLOYMENT_ID':'g7-local',
        'G7_SIEM_DSN':f'postgresql://siem_exporter:{siem}@{address}:5432/audit_sink',
        'G7_AUDIT_ANCHOR_DSN':f'postgresql://exporter_ro:{exporter}@{address}:5432/audit_anchor',
        'G7_AUDIT_ANCHOR_SIGNER_DSN':f'postgresql://anchor_signer:{signer}@{address}:5432/audit_anchor'}
    command=['docker','exec']
    for key,value in envs.items(): command += ['--env',key+'='+value]
    command += [container,'/opt/uvm/venv/bin/python','/opt/uvm/app/tools/g7_container_audit_export.py',
        'siem-export','--limit','5000','--sink-id','g7-siem']
    result=subprocess.run(command,text=True,capture_output=True,check=False)
    capture(pathlib.Path(evidence)/'operational-audit-anchor-export.stdout',result.stdout)
    if result.returncode:
        safe=__import__('re').sub(r'(?i)(password|secret|token|key)(\s*[=:]\s*)[^\s,;]+',r'\1\2[redacted]',result.stderr)
        capture(pathlib.Path(evidence)/'operational-audit-anchor-export.stderr',safe)
        raise RuntimeError('disposable audit anchor export failed; inspect redacted operational-audit-anchor-export.stderr')
    capture(pathlib.Path(evidence)/'operational-audit-anchor-export.command.txt',
        'docker exec <disposable-app> g7_container_audit_export.py siem-export --limit 5000 --sink-id g7-siem\n')
    anchor_command=command[:-5]+['anchor-history','--limit','5000','--sink-id','g7-siem']
    anchored=subprocess.run(anchor_command,text=True,capture_output=True,check=False)
    capture(pathlib.Path(evidence)/'operational-audit-anchor-history.stdout',anchored.stdout)
    if anchored.returncode:
        safe=__import__('re').sub(r'(?i)(password|secret|token|key)(\s*[=:]\s*)[^\s,;]+',r'\1\2[redacted]',anchored.stderr)
        capture(pathlib.Path(evidence)/'operational-audit-anchor-history.stderr',safe)
        raise RuntimeError('disposable audit anchor history failed; inspect redacted operational-audit-anchor-history.stderr')

def exercise_provider_scenarios(catalog, event, runroot, evidence):
    """Exercise real local TLS retry/rejection/ambiguity responses with isolated journals."""
    import copy, ssl
    expected={'rate_limited_once':('accepted',2,['rate_limited',None]),
        'permanent_rejection':('failed',1,['provider_rejected']),
        'accepted_response_lost':('uncertain',1,['submission_uncertain'])}
    secrets_dir=pathlib.Path(runroot)/'secrets'; host_dir=pathlib.Path(runroot)/'host'
    ca=secrets_dir/'recovery-ca.crt'; cert=secrets_dir/'recovery-server.crt'; key=secrets_dir/'recovery-server.key'
    token_file=host_dir/'provider-token'; token=token_file.read_text().strip()
    results=[]
    for scenario,(expected_outcome,expected_count,expected_failures) in expected.items():
        port_sock=socket.socket(); port_sock.bind(('127.0.0.1',0)); port=port_sock.getsockname()[1]; port_sock.close()
        output=pathlib.Path(evidence)/f'provider-{scenario}-requests.json'
        out=(pathlib.Path(evidence)/f'provider-{scenario}.stdout').open('w')
        err=(pathlib.Path(evidence)/f'provider-{scenario}.stderr').open('w')
        proc=subprocess.Popen([sys.executable,str(ROOT/'tools/g7_operational_alert_fixture.py'),
            '--port',str(port),'--output',str(output),'--token-file',str(token_file),
            '--channel',catalog['route']['channel_id'],'--cert',str(cert),'--key',str(key),
            '--scenario',scenario],cwd=ROOT,stdout=out,stderr=err)
        try:
            context=ssl.create_default_context(cafile=str(ca))
            def ready():
                if proc.poll() is not None: return False
                try:
                    with urllib.request.urlopen(f'https://127.0.0.1:{port}/healthz',context=context,timeout=.5) as response:
                        return response.status==200
                except Exception: return False
            wait_for(f'provider-{scenario}',ready,time.monotonic()+10,.1)
            scenario_catalog=copy.deepcopy({k:v for k,v in catalog.items() if not k.startswith('_')})
            scenario_catalog['route']['endpoint']=f'https://127.0.0.1:{port}/api/chat.postMessage'
            scenario_catalog['journal']=str(host_dir/'state'/f'provider-{scenario}.json')
            scenario_catalog_path=host_dir/f'provider-{scenario}-catalog.json'
            capture(scenario_catalog_path,json.dumps(scenario_catalog,sort_keys=True,separators=(',',':'))+'\n')
            loaded=sender.load_catalog(scenario_catalog_path)
            scenario_journal=sender.Journal(loaded['journal'])
            scenario_event=copy.deepcopy(event)
            scenario_event['transition_id']=str(uuid.uuid4())
            scenario_event['episode_id']=str(uuid.uuid4())
            scenario_event['opening_transition_id']=scenario_event['transition_id']
            scenario_event['transition_sequence']=1; scenario_event['predecessor_id']=None
            now=sender.stamp(); scenario_event['observed_at']=now; scenario_event['first_detected_at']=now
            result=sender.send_provider(loaded,scenario_journal,scenario_event)
            if scenario=='rate_limited_once':
                first_records=scenario_journal._read()['records']
                if result['failure_detail']!='rate_limited' or not any(r['kind']=='RETRY_SCHEDULE' for r in first_records):
                    raise RuntimeError('rate limit did not persist a deferred retry schedule')
                # A fresh catalog/journal read models process restart; the retry is admitted once due.
                loaded=sender.load_catalog(scenario_catalog_path)
                result=sender.send_provider(loaded,scenario_journal,scenario_event)
            attempts=[r['attempt'] for r in scenario_journal._read()['records'] if r['kind']=='ATTEMPT_OUTCOME']
            received=json.loads(output.read_text()) if output.exists() else []
            failures=[a['failure_detail'] for a in attempts]
            if result['outcome']!=expected_outcome or len(attempts)!=expected_count or failures!=expected_failures or len(received)!=expected_count or any(r.get('auth_verified') is not True for r in received):
                raise RuntimeError(f'provider scenario {scenario} violated its outcome/retry assertion')
            if scenario=='rate_limited_once' and len({a['attempt_id'] for a in attempts})!=2:
                raise RuntimeError('rate limited retry did not use distinct immutable attempt ids')
            if scenario=='accepted_response_lost' and len(attempts)!=1:
                raise RuntimeError('ambiguous accepted response was resent')
            results.append({'scenario':scenario,'outcome':result['outcome'],'attempt_count':len(attempts),
                'failure_details':failures,'provider_request_count':len(received),
                'tls_verified':True,'ambiguous_resend':False if scenario=='accepted_response_lost' else None})
        finally:
            if proc.poll() is None: proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
            out.close(); err.close()
    capture(pathlib.Path(evidence)/'provider-failure-scenarios.json',json.dumps(results,sort_keys=True,separators=(',',':'))+'\n')
    return results

def main():
    p=argparse.ArgumentParser(); p.add_argument('--container',required=True); p.add_argument('--run-id',required=True); p.add_argument('--api-port',type=int,required=True); p.add_argument('--root',required=True); p.add_argument('--evidence',required=True); p.add_argument('--browser-state',required=True); p.add_argument('--source-root',default=str(ROOT)); p.add_argument('--complete-audit-anchor',action='store_true'); a=p.parse_args()
    runroot=pathlib.Path(a.root); evidence=pathlib.Path(a.evidence); host=runroot/'host'; state=host/'state'; sec=runroot/'secrets'
    if a.complete_audit_anchor:
        complete_local_audit_anchor(a.container,a.run_id,a.root,a.evidence)
        return
    deployment='g7-local'; producer='g7-host-operational-alert-sender/v1'; condition='container_availability'; subject=f'container:g7-local:{a.run_id}'
    app_token=sec/'g7_operational_alert_token'; (host/'api-operational-token').write_text(app_token.read_text()); os.chmod(host/'api-operational-token',0o600)
    bootstrap_env=dict(os.environ,G7_OPERATIONAL_RUN_ID=a.run_id)
    bootstrap=subprocess.run(['docker','exec','-i','--env','G7_OPERATIONAL_RUN_ID='+a.run_id,a.container,'/opt/uvm/venv/bin/python','-'],input=(ROOT/'tools/g7_operational_alert_bootstrap.py').read_text(),text=True,capture_output=True,check=False,env=bootstrap_env)
    capture(evidence/'incident-bootstrap.stdout',bootstrap.stdout)
    if bootstrap.returncode:
        import re
        safe=re.sub(r'(?i)(password|secret|token|key)(\s*[=:]\s*)[^\s,;]+',r'\1\2[redacted]',bootstrap.stderr)
        capture(evidence/'incident-bootstrap.stderr',safe)
        raise RuntimeError('disposable incident bootstrap failed; inspect redacted incident-bootstrap.stderr')
    anchor_started=time.time()
    complete_local_audit_anchor(a.container,a.run_id,a.root,a.evidence)
    def observer_anchor_known():
        try: observed=json.loads((state/'observer-state.json').read_text())
        except (OSError, json.JSONDecodeError): return False
        check=observed.get('last_check') or {}
        try: completed=datetime.fromisoformat(observed['last_completed_loop_at'].replace('Z','+00:00')).timestamp()
        except Exception: return False
        return completed>anchor_started and check.get('anchor_export',{}).get('status') in {'healthy','late'}
    wait_for('fresh-known-anchor-telemetry-after-real-export',observer_anchor_known,time.monotonic()+45,.25)
    capture(evidence/'operational-anchor-telemetry-ready.json',json.dumps({'sink_id':'g7-siem','real_export_and_anchor_history':True,'observer_status':'healthy_or_late','post_export_loop':True},sort_keys=True,separators=(',',':'))+'\n')
    ca=sec/'recovery-ca.crt'; cert=sec/'recovery-server.crt'; key=sec/'recovery-server.key'; tokenfile=host/'provider-token'; tokenfile.write_text(os.urandom(32).hex()); os.chmod(tokenfile,0o600)
    sock=socket.socket(); sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]; sock.close()
    provider_out=(evidence/'provider.stdout').open('w'); provider_err=(evidence/'provider.stderr').open('w')
    provider=subprocess.Popen([sys.executable,str(ROOT/'tools/g7_operational_alert_fixture.py'),'--port',str(port),'--output',str(evidence/'provider-requests.json'),'--token-file',str(tokenfile),'--channel','C_G7_OPERATIONAL_FIXTURE','--cert',str(cert),'--key',str(key)],cwd=ROOT,stdout=provider_out,stderr=provider_err)
    sender_out=(evidence/'sender.stdout').open('w'); sender_err=(evidence/'sender.stderr').open('w'); supervisor_out=(evidence/'supervisor.stdout').open('w'); supervisor_err=(evidence/'supervisor.stderr').open('w')
    sender_proc=supervisor=None; stopped=False; catalog_path=None; catalog=None; health_path=None
    try:
        import ssl
        def provider_ready():
            if provider.poll() is not None: return False
            try: urllib.request.urlopen(f'https://127.0.0.1:{port}/healthz',context=ssl.create_default_context(cafile=str(ca)),timeout=.5).read(); return True
            except Exception: return False
        wait_for('provider-process',provider_ready,time.monotonic()+10,.1)
        image=docker(['inspect',a.container,'--format','{{.Image}}'])
        container_id=docker(['inspect',a.container,'--format','{{.Id}}'])
        catalog={'generation':1,'deployment_id':deployment,'subject_id':subject,'principal_id':'g7-host-operational-alert-sender','producer_id':producer,'condition':condition,'binding_revision':1,'container_id':container_id,'image_id':image,'deployment_label':deployment,'run_label':a.run_id,'recovery_epoch':1,'observer_state':str(state/'observer-state.json'),'supervisor_state':str(state/'supervisor-state.json'),'observer_pidfile':str(host/'observer.pid'),'active_file':str(state/'active.json'),'scheduler_file':str(runroot/'scheduler'/'progress.json'),'observer_readback':str(state/'observer-readback.json'),'supervisor_readback':str(state/'supervisor-readback.json'),'journal':str(host/'state'/'operational-alerts.json'),'health_journal':str(host/'state'/'operational-alert-health.json'),'api_url':f'http://127.0.0.1:{a.api_port}','api_token_file':str(host/'api-operational-token'),'ca_file':str(ca),'route':{'enabled':True,'revision':1,'destination_ref':'g7-operational-fixture-channel','endpoint':f'https://127.0.0.1:{port}/api/chat.postMessage','channel_id':'C_G7_OPERATIONAL_FIXTURE','credential_file':str(tokenfile),'mentions':[],'installation_id':'g7-local-fixture-installation','workspace_id':'T_G7_FIXTURE','runbook_url':'https://example.invalid/g7-operational-runbook'},'retry_count':2,'retry_age_seconds':60,'freshness_seconds':120,'request_deadline_seconds':8,'app_stream_absent_verified':True}
        catalog_path=host/'operational-alert-catalog.json'; capture(catalog_path,json.dumps(catalog,sort_keys=True,separators=(',',':'))+'\n')
        sender_proc=subprocess.Popen([sys.executable,str(ROOT/'tools/g7_operational_alert_sender.py'),'--catalog',str(catalog_path)],cwd=ROOT,stdout=sender_out,stderr=sender_err,start_new_session=True)
        capture(evidence/'sender-process.pid',str(sender_proc.pid)+'\n')
        supervisor=subprocess.Popen([sys.executable,str(ROOT/'tools/g7_operational_alert_sender.py'),'--catalog',str(catalog_path),'--supervise'],cwd=ROOT,stdout=supervisor_out,stderr=supervisor_err,start_new_session=True)
        docker(['stop','--time','10',a.container]); stopped=True; capture(evidence/'app-stop.txt','app_stopped=1\n')
        deadline=time.monotonic()+90
        def accepted_while_down():
            recs=read_records(catalog['journal'])
            intent=next((r for r in recs if r['kind']=='TRANSITION_INTENT'),None)
            outcomes=[r for r in recs if r['kind']=='ATTEMPT_OUTCOME']
            return intent and outcomes and outcomes[0]['attempt']['outcome']=='accepted'
        wait_for('host-send-accepted-while-app-down',accepted_while_down,deadline)
        if docker(['inspect',a.container,'--format','{{.State.Status}}'])!='exited': raise RuntimeError('application container was not stopped during host acceptance')
        records=read_records(catalog['journal'])
        opening=next(r for r in records if r['kind']=='TRANSITION_INTENT' and r['event']['transition_kind']=='opened')
        accepted=next(r for r in records if r['kind']=='ATTEMPT_OUTCOME' and r['attempt']['outcome']=='accepted')
        capture(evidence/'host-send-while-app-down.json',json.dumps({'app_state':'exited','transition_id':opening['event']['transition_id'],'attempt_id':accepted['attempt']['attempt_id'],'outcome':'accepted','provider_acceptance':True},sort_keys=True,separators=(',',':'))+'\n')
        # Pause before the first recovery opportunity, otherwise a quick healthy
        # startup can close the episode before the restart-fence exercise begins.
        os.kill(sender_proc.pid,signal.SIGSTOP)
        docker(['start',a.container]); stopped=False
        wait_for('app-healthy-after-restart',lambda: docker(['inspect',a.container,'--format','{{.State.Health.Status}}'])=='healthy',time.monotonic()+240)
        # Hold the host sender across recovery and two further target restarts.
        # The resumed process must rebase qualification on the latest StartedAt.
        restart_one=docker(['inspect',a.container,'--format','{{.State.StartedAt}}'])
        docker(['stop','--time','10',a.container]); stopped=True
        docker(['start',a.container]); stopped=False
        wait_for('first-post-outage-restart-healthy',lambda: docker(['inspect',a.container,'--format','{{.State.Health.Status}}'])=='healthy',time.monotonic()+240)
        first_started=docker(['inspect',a.container,'--format','{{.State.StartedAt}}'])
        docker(['stop','--time','10',a.container]); stopped=True
        docker(['start',a.container]); stopped=False
        wait_for('second-post-outage-restart-healthy',lambda: docker(['inspect',a.container,'--format','{{.State.Health.Status}}'])=='healthy',time.monotonic()+240)
        second_started=docker(['inspect',a.container,'--format','{{.State.StartedAt}}'])
        os.kill(sender_proc.pid,signal.SIGCONT)
        capture(evidence/'recovery-restart-barrier-inputs.json',json.dumps(
            {'first_started_at':first_started,'second_started_at':second_started,
             'initial_started_at':restart_one,'sender_paused_across_both_restarts':True},
            sort_keys=True,separators=(',',':'))+'\n')
        deadline=time.monotonic()+360
        def rebased_barrier():
            records=read_records(catalog['journal'])
            return any(r.get('kind')=='RECOVERY_BARRIER' and r.get('started_at')==second_started
                and any(b.get('kind')=='OUTAGE_BARRIER' and b.get('sequence')==r.get('source_outage_barrier_sequence')
                    and b.get('target_started_at')==second_started for b in records)
                for r in records)
        wait_for('recovery-barrier-rebased-after-second-container-start',rebased_barrier,deadline)
        capture(evidence/'recovery-rebased-barrier-confirmed.json',json.dumps(
            {'second_started_at':second_started,'barrier_rebased':True},sort_keys=True,separators=(',',':'))+'\n')
        def caught_up():
            records=read_records(catalog['journal'])
            transitions={r.get('transition_id') for r in records if r['kind']=='TRANSITION_ACK'}
            attempts={r.get('attempt_id') for r in records if r['kind']=='ATTEMPT_ACK'}
            expected={r['event']['transition_id'] for r in records if r['kind']=='TRANSITION_INTENT'}
            expected_attempts={r['attempt']['attempt_id'] for r in records if r['kind']=='ATTEMPT_OUTCOME'}
            return bool(expected) and expected<=transitions and expected_attempts<=attempts and any(r['event']['transition_kind']=='recovered' for r in records if r['kind']=='TRANSITION_INTENT')
        wait_for('ordered-public-projection-catchup-and-recovery',caught_up,deadline)
        state_doc=json.loads(pathlib.Path(a.browser_state).read_text()); cookie=next(c['value'] for c in state_doc['cookies'] if c['name']=='uvm_session')
        base=f"http://127.0.0.1:{a.api_port}"
        def session_request(path):
            req=urllib.request.Request(base+path,headers={'Cookie':'uvm_session='+cookie,'Accept':'application/json'})
            try:
                with urllib.request.urlopen(req,timeout=15) as response:
                    return response.status,response.read()
            except urllib.error.HTTPError as error:
                return error.code,error.read()
        auth_status,auth_body=session_request('/api/v1/auth/session')
        capture(evidence/'post-restart-session-check.json',json.dumps({'status':auth_status,'body':json.loads(auth_body)},sort_keys=True,separators=(',',':'))+'\n')
        public_status,public_body=session_request(f'/api/v1/integrations/incidents?deployment_id={deployment}')
        capture(evidence/'public-current-recipient-response.json',json.dumps({'status':public_status,'body':json.loads(public_body)},sort_keys=True,separators=(',',':'))+'\n')
        if public_status!=200: raise RuntimeError(f'current recipient public incident read returned HTTP {public_status}; see retained session and response evidence')
        public=json.loads(public_body)
        items=public.get('items',[])
        availability_items=[item for item in items if item.get('subject_id')==subject]
        if len(availability_items)<2: raise RuntimeError('current recipient group did not read both public availability incident edges')
        capture(evidence/'public-current-recipient-read.json',json.dumps({'schema_version':public.get('schema_version'),'item_count':len(availability_items),'transition_kinds':[x.get('transition_kind') for x in availability_items],'subject_id':subject},sort_keys=True,separators=(',',':'))+'\n')
        exercise_provider_scenarios(catalog,opening['event'],runroot,evidence)
        # The separate supervisor remains observable if the sender dies while UVM is unavailable.
        docker(['stop','--time','10',a.container]); stopped=True
        os.kill(sender_proc.pid,signal.SIGKILL); sender_proc.wait(timeout=5)
        health_path=pathlib.Path(catalog['health_journal'])
        wait_for('independent-supervisor-detects-dead-sender',lambda: health_path.exists() and any(r['kind']=='SENDER_HEALTH_EDGE' and r.get('state')=='dead' for r in read_records(str(health_path))),time.monotonic()+20)
        capture(evidence/'independent-sender-death-observed.json',json.dumps({'app_state':'exited','sender_state':'dead','independent_health_journal':str(health_path)},sort_keys=True,separators=(',',':'))+'\n')
        docker(['start',a.container]); stopped=False
        wait_for('app-healthy-after-sender-supervision',
            lambda: docker(['inspect',a.container,'--format','{{.State.Health.Status}}'])=='healthy',
            time.monotonic()+240)
        # Resume the verified sender. It must make a real notification attempt and
        # only then project the supervisor's original fault/recovery edges.
        sender_proc=subprocess.Popen([sys.executable,str(ROOT/'tools/g7_operational_alert_sender.py'),'--catalog',str(catalog_path)],cwd=ROOT,stdout=sender_out,stderr=sender_err,start_new_session=True)
        capture(evidence/'sender-resumed.pid',str(sender_proc.pid)+'\n')
        health_subject=f"host-sender:{deployment}:{a.run_id}"
        def health_projected():
            rows=read_records(str(health_path))
            intents=[r for r in rows if r.get('kind')=='HEALTH_TRANSITION_INTENT'
                and r.get('event',{}).get('subject_id')==health_subject]
            acked={r.get('transition_id') for r in rows if r.get('kind')=='HEALTH_TRANSITION_ACK'}
            outcomes=[r for r in rows if r.get('kind')=='ATTEMPT_OUTCOME']
            attempts={r.get('attempt_id') for r in rows if r.get('kind')=='ATTEMPT_ACK'}
            return (any(r.get('transition_id') in acked for r in intents) and
                bool(outcomes) and all(r['attempt']['attempt_id'] in attempts for r in outcomes) and
                any(r['attempt']['outcome']=='accepted' for r in outcomes) and
                {r['event']['transition_kind'] for r in intents}>={'opened','recovered'})
        wait_for('resumed-sender-health-notification-and-projection',health_projected,time.monotonic()+90)
        health_status,health_body=session_request(f'/api/v1/integrations/incidents?deployment_id={deployment}')
        capture(evidence/'public-supervisor-health-response.json',json.dumps(
            {'status':health_status,'body':json.loads(health_body)},sort_keys=True,separators=(',',':'))+'\n')
        if health_status!=200:
            raise RuntimeError(f'independent sender health public read returned HTTP {health_status}')
        health_items=[item for item in json.loads(health_body).get('items',[])
            if item.get('subject_id')==health_subject]
        if not {'opened','recovered'} <= {item.get('transition_kind') for item in health_items
                if item.get('condition')=='host_sender_health'}:
            raise RuntimeError('resumed sender health opened/recovered transitions are absent from public projection')
        capture(evidence/'public-supervisor-health-read.json',json.dumps(
            {'subject_id':health_subject,'transition_kinds':[item.get('transition_kind') for item in health_items]},
            sort_keys=True,separators=(',',':'))+'\n')
        print(json.dumps({'result':'app-down-host-send-and-public-catchup-passed','run_id':a.run_id,'container_id':container_id,'provider_acceptance':'accepted','public_items':len(availability_items),'public_sender_health_items':len(health_items),'sender_death_observed':True}))
    finally:
        if sender_proc and sender_proc.poll() is None:
            try: os.kill(sender_proc.pid,signal.SIGCONT)
            except ProcessLookupError: pass
        if stopped:
            try: docker(['start',a.container])
            except Exception: pass
        for proc in (sender_proc,supervisor,provider):
            if proc and proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
        for stream in (provider_out,provider_err,sender_out,sender_err,supervisor_out,supervisor_err): stream.close()
        # Preserve the exact private run inputs and durable consumer state before
        # the enclosing runner removes RUN_ROOT. Files are mode 0600 and contain
        # no credential material (only protected paths/references).
        import shutil
        retain=[]
        if catalog_path is not None: retain.append((catalog_path,'operational-alert-catalog.json'))
        if catalog is not None:
            for key,name in (('journal','operational-alert-journal.json'),
                    ('health_journal','operational-alert-health-journal.json')):
                path=pathlib.Path(catalog[key]); retain.append((path,name))
                retain.append((path.with_suffix(path.suffix+'.genesis'),name+'.genesis'))
            for key,name in (('observer_state','observer-state.snapshot.json'),
                    ('active_file','active-timing.snapshot.json'),
                    ('observer_readback','observer-readback.snapshot.json'),
                    ('supervisor_state','supervisor-state.snapshot.json'),
                    ('supervisor_readback','supervisor-readback.snapshot.json')):
                retain.append((pathlib.Path(catalog[key]),name))
            retain.append((pathlib.Path(catalog['scheduler_file']),'scheduler-progress.snapshot.json'))
        for source,name in retain:
            try:
                target=evidence/name; target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                shutil.copyfile(source,target); os.chmod(target,0o600)
            except FileNotFoundError: pass
        try:
            inspected=json.loads(docker(['inspect',a.container]))[0]
            state=inspected.get('State',{}); config=inspected.get('Config',{})
            image_context={'container_id':inspected.get('Id'),'image_id':inspected.get('Image'),
                'labels':{k:v for k,v in (config.get('Labels') or {}).items() if k.startswith('uvm.')},
                'state':{'Status':state.get('Status'),'Running':state.get('Running'),'Paused':state.get('Paused'),
                    'StartedAt':state.get('StartedAt'),'FinishedAt':state.get('FinishedAt'),
                    'Health':(state.get('Health') or {}).get('Status')}}
            capture(evidence/'inspected-source-context.json',json.dumps(image_context,sort_keys=True,separators=(',',':'))+'\n')
        except Exception: pass
if __name__=='__main__': main()
