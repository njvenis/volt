#!/usr/bin/env python3
"""Host-only durable G7 operational alert sender; never mounted into UVM."""
from __future__ import annotations
import argparse, datetime as dt, fcntl, hashlib, json, os, re, ssl, subprocess, sys, time, urllib.error, urllib.request, uuid
from pathlib import Path
from urllib.parse import urlparse

UTC = dt.timezone.utc
FAILURE_CODES = {'provider_rejected','rate_limited','provider_unavailable','transport_pre_submit','response_invalid','submission_uncertain','local_persistence_failed'}
OBSERVER_MAX_FUTURE_SKEW_SECONDS = 30

def stamp(value=None):
    value = value or dt.datetime.now(UTC)
    return value.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def sha(value): return hashlib.sha256(value).hexdigest()
def fsync_dir(path):
    fd=os.open(str(path),os.O_RDONLY | getattr(os,'O_DIRECTORY',0))
    try: os.fsync(fd)
    finally: os.close(fd)
def atomic(path, data):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    tmp=path.with_name(path.name+'.tmp-'+uuid.uuid4().hex)
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd,'wb') as out: out.write(data); out.flush(); os.fsync(out.fileno())
        os.replace(tmp,path); fsync_dir(path.parent)
    finally:
        try: tmp.unlink()
        except FileNotFoundError: pass

def load_catalog(path):
    raw=Path(path).read_bytes(); c=json.loads(raw)
    required={'generation','deployment_id','subject_id','principal_id','producer_id','condition','binding_revision','container_id','image_id','deployment_label','run_label','recovery_epoch','observer_state','supervisor_state','observer_pidfile','active_file','scheduler_file','observer_readback','supervisor_readback','journal','health_journal','api_url','api_token_file','ca_file','route','retry_count','retry_age_seconds','freshness_seconds','request_deadline_seconds','app_stream_absent_verified'}
    if not isinstance(c,dict) or set(c)!=required or type(c['generation']) is not int or c['generation']<1: raise ValueError('catalog-shape-invalid')
    if c['condition'] not in {'container_availability','host_sender_health'}: raise ValueError('catalog-condition-invalid')
    if type(c['app_stream_absent_verified']) is not bool: raise ValueError('catalog-genesis-proof-invalid')
    api=urlparse(c['api_url']); route=c['route']
    route_fields={'enabled','revision','destination_ref','endpoint','channel_id','credential_file','mentions','installation_id','workspace_id','runbook_url'}
    provider=urlparse(route.get('endpoint','')) if isinstance(route,dict) else urlparse('')
    if (api.scheme not in {'http','https'} or api.hostname not in {'127.0.0.1','localhost','::1'}
            or not isinstance(route,dict) or set(route)!=route_fields
            or type(route.get('enabled')) is not bool or type(route.get('revision')) is not int
            or route['revision']<1 or not isinstance(route.get('destination_ref'),str) or not route['destination_ref']
            or provider.scheme!='https' or not provider.hostname or not isinstance(route.get('mentions'),list)):
        raise ValueError('catalog-route-invalid')
    for k in ('binding_revision','retry_count','retry_age_seconds','freshness_seconds','request_deadline_seconds'):
        if type(c[k]) is not int or c[k] < (1 if k!='retry_count' else 0): raise ValueError('catalog-bound-invalid')
    if c['retry_count']>5 or c['retry_age_seconds']>300 or c['freshness_seconds']>86400 or c['request_deadline_seconds']>60:
        raise ValueError('catalog-bound-invalid')
    c['_path']=str(Path(path).resolve()); c['_digest']=sha(canonical(c)); return c

class Journal:
    def __init__(self,path):
        self.path=Path(path); self.lock=self.path.with_suffix(self.path.suffix+'.lock')
    def _read(self):
        if not self.path.exists(): return {'version':1,'sequence':0,'head':'0'*64,'records':[]}
        try: doc=json.loads(self.path.read_bytes())
        except Exception as exc: raise RuntimeError('journal-corrupt') from exc
        if not isinstance(doc,dict) or set(doc)!={'version','sequence','head','records'} or doc['version']!=1 or not isinstance(doc['records'],list): raise RuntimeError('journal-corrupt')
        prev='0'*64
        for i,r in enumerate(doc['records'],1):
            if not isinstance(r,dict) or r.get('sequence')!=i or r.get('previous_digest')!=prev: raise RuntimeError('journal-chain-invalid')
            digest=r.get('digest'); body={k:v for k,v in r.items() if k!='digest'}
            if digest!=sha(canonical(body)): raise RuntimeError('journal-digest-invalid')
            prev=digest
        if doc['sequence']!=len(doc['records']) or doc['head']!=prev: raise RuntimeError('journal-head-invalid')
        return doc
    def append(self,kind,fields):
        self.lock.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        fd=os.open(self.lock,os.O_RDWR|os.O_CREAT,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX); doc=self._read(); body={'sequence':doc['sequence']+1,'previous_digest':doc['head'],'at':stamp(),'kind':kind,**fields}; body['digest']=sha(canonical(body)); doc['records'].append(body); doc['sequence']=body['sequence']; doc['head']=body['digest']; atomic(self.path,canonical(doc)+b'\n'); return body
        finally: fcntl.flock(fd,fcntl.LOCK_UN); os.close(fd)

def inspect_target(c):
    # The only Docker operation this process can invoke is inspect for one configured ID.
    p=subprocess.run(['docker','inspect','--type','container',c['container_id']],capture_output=True,text=True,timeout=8,check=False)
    if p.returncode: return {'state':'unknown','reason':'inspect-unavailable'}
    try: data=json.loads(p.stdout)
    except Exception: return {'state':'unknown','reason':'inspect-malformed'}
    if not isinstance(data,list) or len(data)!=1: return {'state':'unknown','reason':'inspect-identity'}
    x=data[0]; labels=x.get('Config',{}).get('Labels') or {}; state=x.get('State',{})
    identity=(x.get('Id')==c['container_id'] and x.get('Image')==c['image_id'] and labels.get('uvm.deployment_id')==c['deployment_label'] and labels.get('uvm.run_id')==c['run_label'])
    if not identity: return {'state':'unknown','reason':'target-context-changed'}
    status=state.get('Status'); mapped={'running':'running','exited':'exited','created':'unknown','restarting':'unknown','paused':'unknown','dead':'unknown'}
    return {'state':mapped.get(status,'unknown'),'started_at':state.get('StartedAt'),'container_id':x.get('Id'),'image_id':x.get('Image'),'deployment_label':labels.get('uvm.deployment_id'),'run_label':labels.get('uvm.run_id'),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}

def read_json(path):
    try: return json.loads(Path(path).read_text())
    except Exception: return None


def causal_sample(value, not_before_epoch, *, now_epoch=None, future_skew_seconds=OBSERVER_MAX_FUTURE_SKEW_SECONDS):
    """Accept only parseable, causally new samples within the bounded future window."""
    if not isinstance(value,str) or type(not_before_epoch) not in (int,float): return False
    try: epoch=dt.datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()
    except Exception: return False
    now_epoch=time.time() if now_epoch is None else now_epoch
    return not_before_epoch<epoch<=now_epoch+future_skew_seconds

def post_json(url, token, body, *, ca_file=None, timeout=15):
    req=urllib.request.Request(url,data=canonical(body),headers={'Authorization':'Bearer '+token,'Content-Type':'application/json','Accept':'application/json'},method='POST')
    ctx=ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*a,**kw): return None
    handlers=[NoRedirect()]
    if url.startswith('https://'): handlers.append(urllib.request.HTTPSHandler(context=ctx))
    else: handlers.append(urllib.request.HTTPHandler())
    opener=urllib.request.build_opener(*handlers)
    with opener.open(req,timeout=timeout) as res:
        raw=res.read(16385)
        if len(raw)>16384: raise ValueError('ack-too-large')
        return res.status,json.loads(raw)


def api_post(c,path,body):
    token=Path(c['api_token_file']).read_text().strip()
    return post_json(c['api_url'].rstrip('/')+path,token,body,timeout=c['request_deadline_seconds'])


def current_route(c):
    route=c['route']
    if not isinstance(route,dict) or set(route)!={'enabled','revision','destination_ref','endpoint','channel_id','credential_file','mentions','installation_id','workspace_id','runbook_url'}: raise ValueError('route-shape-invalid')
    if route['enabled'] is not True or not route['endpoint'].startswith('https://'): raise ValueError('route-disabled-or-insecure')
    return route


def replace_catalog(path, document):
    """Serialize an operator catalog update against in-flight provider dispatch."""
    path=Path(path); lock=path.with_suffix('.lock')
    fd=os.open(lock,os.O_RDWR|os.O_CREAT,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        atomic(path,canonical(document)+b'\n')
        return load_catalog(path)
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN); os.close(fd)


def delivery_body(event, route):
    text=(f"{event['condition']}: deployment health changed ({event['transition_kind']}). "
        f"Incident {event['episode_id']} at {event['observed_at']}. Runbook: {route['runbook_url']}")
    if route['mentions']:
        text += " " + " ".join("<@"+m+">" for m in route['mentions'])
    return {'channel':route['channel_id'],'text':text,'metadata':{'event_type':'uvm_g7_operational_alert','event_payload':{'condition':event['condition'],'incident_id':event['episode_id'],'transition_kind':event['transition_kind'],'observed_at':event['observed_at']}}}


def send_provider(c,j,event):
    request_body=delivery_body(event,c['route'])
    first_attempt=time.monotonic()
    for retry_index in range(c['retry_count']+1):
        attempt={'schema_version':1,'attempt_id':str(uuid.uuid4()),'outcome':'uncertain','attempted_at':stamp(),'receipt_ref':None,'failure_detail':'submission_uncertain'}
        catalog_lock=Path(c['_path']).with_suffix('.lock'); fd=os.open(catalog_lock,os.O_RDWR|os.O_CREAT,0o600)
        retry_after=None
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            current=load_catalog(c['_path'])
            if current['_digest']!=c['_digest'] or current['route']!=c['route']:
                j.append('HELD',{'reason':'catalog-or-route-changed-before-dispatch','transition_id':event['transition_id']})
                return attempt
            route=current_route(current)
            credential=Path(route['credential_file']).read_text().strip()
            j.append('SENDING',{'transition_id':event['transition_id'],'attempt':attempt,'route_revision':route['revision'],'route_digest':sha(canonical(route)),'catalog_generation':c['generation'],'catalog_digest':c['_digest'],'request_digest':sha(canonical(request_body))})
            try:
                status,response=post_json(route['endpoint'],credential,request_body,ca_file=c['ca_file'],timeout=c['request_deadline_seconds'])
                if (200<=status<300 and isinstance(response,dict) and response.get('ok') is True
                        and response.get('channel')==route['channel_id'] and isinstance(response.get('ts'),str) and response['ts']):
                    attempt.update(outcome='accepted',receipt_ref='provider:'+re.sub(r'[^A-Za-z0-9._:-]','',response['ts'])[:200],failure_detail=None)
                elif status==429:
                    attempt.update(outcome='failed',failure_detail='rate_limited')
                elif 400<=status<500:
                    attempt.update(outcome='failed',failure_detail='provider_rejected')
                else:
                    attempt.update(outcome='uncertain',failure_detail='response_invalid')
            except urllib.error.HTTPError as exc:
                if exc.code==429:
                    attempt.update(outcome='failed',failure_detail='rate_limited')
                    raw_delay=exc.headers.get('Retry-After','') if exc.headers else ''
                    if re.fullmatch(r'[0-9]{1,4}',raw_delay): retry_after=min(int(raw_delay),30)
                elif exc.code in {400,401,403,404,422}:
                    attempt.update(outcome='failed',failure_detail='provider_rejected')
                else:
                    attempt.update(outcome='uncertain',failure_detail='submission_uncertain')
            except (urllib.error.URLError,TimeoutError,ConnectionError,ssl.SSLError):
                # Transport failure cannot prove whether the provider saw the request.
                attempt.update(outcome='uncertain',failure_detail='submission_uncertain')
            j.append('ATTEMPT_OUTCOME',{'transition_id':event['transition_id'],'attempt':attempt,'outcome_completed_at':stamp()})
        finally:
            fcntl.flock(fd,fcntl.LOCK_UN); os.close(fd)
        if attempt['outcome']!='failed' or attempt['failure_detail']!='rate_limited' or retry_index>=c['retry_count']:
            return attempt
        if retry_after is None or time.monotonic()-first_attempt+retry_after>c['retry_age_seconds']:
            return attempt
        time.sleep(retry_after)
    return attempt


def project_pending(c,j,records):
    for record in records:
        if record['kind']!='TRANSITION_INTENT': continue
        event=record['event']; tid=event['transition_id']
        transition_ack=any(r['kind']=='TRANSITION_ACK' and r.get('transition_id')==tid for r in records)
        if not transition_ack:
            try: status,response=api_post(c,'/api/v1/integrations/incidents',event)
            except Exception: return
            digest=sha(canonical(event))
            if status not in (200,201) or not ack_transition(response,event,digest): return
            j.append('TRANSITION_ACK',{'transition_id':tid,'ack':response})
            records.append(j._read()['records'][-1])
        attempts=[r['attempt'] for r in records if r['kind']=='ATTEMPT_OUTCOME' and r.get('transition_id')==tid]
        for attempt in attempts:
            already=any(r['kind']=='ATTEMPT_ACK' and r.get('attempt_id')==attempt['attempt_id'] for r in records)
            if already: continue
            try: status,response=api_post(c,f"/api/v1/integrations/incidents/{tid}/delivery",attempt)
            except Exception: return
            if status not in (200,201) or not ack_attempt(response,tid,attempt): return
            j.append('ATTEMPT_ACK',{'transition_id':tid,'attempt_id':attempt['attempt_id'],'ack':response})
            records.append(j._read()['records'][-1])

def ack_transition(response,event,digest):
    keys={'schema_version','status','transition_id','transition_sequence','episode_id','episode_generation','payload_digest'}
    return isinstance(response,dict) and set(response)==keys and type(response['schema_version']) is int and response=={'schema_version':1,'status':'projected','transition_id':event['transition_id'],'transition_sequence':event['transition_sequence'],'episode_id':event['episode_id'],'episode_generation':event['episode_generation'],'payload_digest':digest}
def ack_attempt(response, transition, attempt, replay=False):
    keys={'schema_version','status','transition_id','attempt_id','outcome','idempotent'} | (set() if replay else {'superseded'})
    return isinstance(response,dict) and set(response)==keys and type(response.get('schema_version')) is int and response.get('schema_version')==1 and response.get('status')=='projected' and response.get('transition_id')==transition and response.get('attempt_id')==attempt['attempt_id'] and response.get('outcome')==attempt['outcome'] and response.get('idempotent') is replay and (replay or response.get('superseded') is False)

def observer_recovery(c, previous):
    """Conservative two-loop barrier; missing fields remain unknown."""
    state=read_json(c['observer_state'])
    if not isinstance(state,dict): return False
    last=state.get('last_check') or {}; seq=state.get('loop_sequence'); completed=state.get('last_completed_loop_at')
    if type(seq) is not int or not isinstance(completed,str) or not isinstance(last.get('at'),str): return False
    try: done=dt.datetime.fromisoformat(completed.replace('Z','+00:00')); at=dt.datetime.fromisoformat(last['at'].replace('Z','+00:00'))
    except ValueError: return False
    proc=previous.get('observer_proc')
    if not proc or previous.get('boot_id')!=Path('/proc/sys/kernel/random/boot_id').read_text().strip(): return False
    try:
        stat=Path(f"/proc/{proc['pid']}/stat").read_text().split()
        if stat[21]!=proc['start_ticks']: return False
    except Exception: return False
    supervisor=read_json(c['supervisor_state']) or {}; active=read_json(c['active_file']) or {}
    scheduler=read_json(c['scheduler_file']) or {}
    def fresh_readback(path):
        row=read_json(path) or {}
        try: age=(time.time()-dt.datetime.fromisoformat(row['observed_at'].replace('Z','+00:00')).timestamp())
        except Exception: return False
        return 0<=age<=c['freshness_seconds'] and row.get('revision')==previous.get('timing_revision') and row.get('digest')==previous.get('timing_digest')
    started=dt.datetime.fromisoformat(current_started(c).replace('Z','+00:00')).timestamp()
    floor=max(previous.get('barrier_completed_epoch',0),started)
    skew=previous.get('future_skew_seconds')
    if type(skew) is not int or not 0<=skew<=3600: return False
    return (seq>previous.get('loop_sequence',0) and causal_sample(completed,floor,future_skew_seconds=skew) and causal_sample(last['at'],floor,future_skew_seconds=skew) and last.get('http_status')==200 and last.get('error') is None and (last.get('anchor_export') or {}).get('status') in {'healthy','late'} and (last.get('incident_projection') or {}).get('status') in {'healthy','late'} and (state.get('scheduler') or {}).get('status')=='healthy' and type(scheduler.get('loop_sequence')) is int and scheduler.get('boot_id')==previous.get('boot_id') and state.get('active_revision')==previous.get('timing_revision') and state.get('active_digest')==previous.get('timing_digest') and active.get('revision')==previous.get('timing_revision') and active.get('digest')==previous.get('timing_digest') and (supervisor.get('supervision') or {}).get('status')=='healthy' and fresh_readback(c['observer_readback']) and fresh_readback(c['supervisor_readback']) and time.monotonic_ns()>previous.get('monotonic_ns',0))


def current_started(c):
    inspected=inspect_target(c)
    if inspected.get('state')!='running' or not inspected.get('started_at'): raise ValueError('restart-identity-unavailable')
    return inspected['started_at']


def observer_identity(c):
    try:
        pid=int(Path(c['observer_pidfile']).read_text().strip())
        fields=Path(f'/proc/{pid}/stat').read_text().split()
        return {'pid':pid,'start_ticks':fields[21]}
    except Exception: return None


def bound_context(c, inspected):
    """Stable identity for old journal work; restart time is deliberately excluded."""
    route=c['route']
    return {
        'deployment_id':c['deployment_id'], 'subject_id':c['subject_id'],
        'principal_id':c['principal_id'], 'producer_id':c['producer_id'],
        'condition':c['condition'], 'binding_revision':c['binding_revision'],
        'catalog_generation':c['generation'], 'catalog_digest':c['_digest'],
        'recovery_epoch':c['recovery_epoch'], 'container_id':inspected.get('container_id'),
        'image_id':inspected.get('image_id'),
        'deployment_label':inspected.get('deployment_label'),
        'run_label':inspected.get('run_label'), 'boot_id':inspected.get('boot_id'),
        'route_revision':route.get('revision'),
        'route_digest':sha(canonical(route)),
    }


def recovery_barrier(c, prior):
    state=read_json(c['observer_state']) or {}; seq=state.get('loop_sequence'); completed=state.get('last_completed_loop_at')
    identity=observer_identity(c); ctx=inspect_target(c)
    if type(seq) is not int or not isinstance(completed,str) or not identity or ctx.get('state')!='running' or ctx.get('boot_id')!=prior.get('boot_id'): return None
    try:
        done=dt.datetime.fromisoformat(completed.replace('Z','+00:00')); started=dt.datetime.fromisoformat(ctx['started_at'].replace('Z','+00:00'))
    except Exception: return None
    baseline=prior.get('loop_sequence')
    active=read_json(c['active_file']) or {}; values=active.get('values')
    skew=values.get('maximum_future_skew_seconds') if isinstance(values,dict) else None
    if type(skew) is not int or not 0<=skew<=3600: return None
    floor=max(started.timestamp(),prior.get('outage_observed_epoch',0))
    if (type(baseline) is not int or seq<=baseline or not causal_sample(completed,floor,future_skew_seconds=skew)
            or identity!=prior.get('observer_proc') or ctx.get('boot_id')!=prior.get('boot_id')): return None
    if (type(active.get('revision')) is not int or not isinstance(active.get('digest'),str)
            or active.get('revision')!=prior.get('timing_revision')
            or active.get('digest')!=prior.get('timing_digest')): return None
    return {'loop_sequence':seq,'barrier_completed_epoch':done.timestamp(),'observer_proc':identity,'boot_id':ctx['boot_id'],'timing_revision':active['revision'],'timing_digest':active['digest'],'future_skew_seconds':skew,'monotonic_ns':time.monotonic_ns(),'started_at':ctx['started_at']}

def edge(c,j,kind,inspection,first=None,episode=None,opening_id=None,seq=1,pred=None,generation=1):
    now=stamp(); tid=str(uuid.uuid4()); ep=episode or str(uuid.uuid4())
    opening_id=tid if kind=='opened' else opening_id
    event={'schema_version':1,'deployment_id':c['deployment_id'],'subject_id':c['subject_id'],'condition':c['condition'],'transition_id':tid,'transition_sequence':seq,'predecessor_id':pred,'episode_id':ep,'opening_transition_id':opening_id,'episode_generation':generation,'transition_kind':kind,'configuration_revision':c['binding_revision'],'first_detected_at':first or now,'observed_at':now,'recovered_at':now if kind=='recovered' else None,'evidence_refs':['host-inspection:'+sha(canonical(inspection))[:24]],'producer_id':c['producer_id']}
    j.append('TRANSITION_INTENT',{'transition_id':tid,'api_sequence':seq,'payload_digest':sha(canonical(event)),'event':event,'context':bound_context(c,inspection)})
    return event


def record_interrupted_sends(j, records):
    """Close every durable SENDING without an outcome as uncertain, never retry it."""
    known={r.get('attempt',{}).get('attempt_id') for r in records
        if r.get('kind')=='ATTEMPT_OUTCOME'}
    recovered=[]
    for sent in records:
        if sent.get('kind')!='SENDING' or sent.get('attempt',{}).get('attempt_id') in known:
            continue
        attempt=dict(sent['attempt'])
        attempt.update(outcome='uncertain',failure_detail='submission_uncertain')
        recovered.append(j.append('ATTEMPT_OUTCOME',{'transition_id':sent['transition_id'],
            'attempt':attempt,'outcome_completed_at':stamp(),'recovered_sending_after_restart':True}))
    return recovered


def project_supervisor_health(c, health):
    """Project truthful supervisor fault edges; this path never sends a provider alert."""
    records=health._read()['records']
    intents=[r for r in records if r.get('kind')=='HEALTH_TRANSITION_INTENT']
    acked={r.get('transition_id') for r in records if r.get('kind')=='HEALTH_TRANSITION_ACK'}
    for intent in intents:
        event=intent['event']
        if event['transition_id'] in acked: continue
        try: status,response=api_post(c,'/api/v1/integrations/incidents',event)
        except Exception: return
        digest=sha(canonical(event))
        if status not in (200,201) or not ack_transition(response,event,digest): return
        health.append('HEALTH_TRANSITION_ACK',{'transition_id':event['transition_id'],'ack':response})
        acked.add(event['transition_id'])
    latest_state=next((r.get('state') for r in reversed(records)
        if r.get('kind')=='SENDER_HEALTH_EDGE'),None)
    if latest_state is None or (latest_state=='healthy' and not intents): return
    active=None
    for intent in intents:
        event=intent['event']
        if event['transition_kind']=='opened': active=intent
        elif event['transition_kind']=='recovered': active=None
    if latest_state=='healthy' and active is None: return
    if latest_state!='healthy' and active is not None: return
    transition_id=str(uuid.uuid4()); now=stamp()
    sequence=len(intents)+1
    predecessor=intents[-1]['event']['transition_id'] if intents else None
    generation=sum(1 for r in intents if r['event']['transition_kind']=='opened')
    if latest_state!='healthy':
        kind='opened'; generation+=1; episode=str(uuid.uuid4()); opening=transition_id
        first=now; recovered=None
    else:
        opening_event=active['event']; kind='recovered'; episode=opening_event['episode_id']
        opening=opening_event['opening_transition_id']; generation=opening_event['episode_generation']
        first=opening_event['first_detected_at']; recovered=now
    health_edge=next(r for r in reversed(records) if r.get('kind')=='SENDER_HEALTH_EDGE'
        and r.get('state')==latest_state)
    subject=f"host-sender:{c['deployment_id']}:{c['run_label']}"
    event={'schema_version':1,'deployment_id':c['deployment_id'],'subject_id':subject,
        'condition':'host_sender_health','transition_id':transition_id,'transition_sequence':sequence,
        'predecessor_id':predecessor,'episode_id':episode,'opening_transition_id':opening,
        'episode_generation':generation,'transition_kind':kind,
        'configuration_revision':c['binding_revision'],'first_detected_at':first,
        'observed_at':now,'recovered_at':recovered,
        'evidence_refs':['host-supervisor:'+health_edge['digest'][:24]],'producer_id':c['producer_id']}
    health.append('HEALTH_TRANSITION_INTENT',{'transition_id':transition_id,'event':event,
        'actor':'independent_host_supervisor','binding_revision':c['binding_revision'],
        'route_revision':c['route']['revision'],'health_journal_head':health_edge['digest']})
    project_supervisor_health(c,health)

def run_once(c):
    j=Journal(c['journal']); doc=j._read(); records=doc['records']; current=inspect_target(c)
    ctx=bound_context(c,current)
    prior_context=next((r['context'] for r in reversed(records)
        if r.get('kind')=='TRANSITION_INTENT' and isinstance(r.get('context'),dict)),None)
    if prior_context and prior_context!=ctx:
        j.append('HELD',{'reason':'bound-service-context-changed','prior_context':prior_context,'context':ctx}); return 3
    j.append('INSPECTION',{'state':current['state'],'context_digest':sha(canonical(ctx)),'context':ctx,'reason':current.get('reason')})
    # A durable SENDING without a durable result is always uncertain after restart.
    record_interrupted_sends(j,records)
    records=j._read()['records']
    # Persist the terminal local outcome before trying any app projection. The app
    # may be offline or the Docker inspection may be unknown during this restart.
    if current['state']=='unknown': return 0
    project_pending(c,j,records)
    edges=[r for r in records if r['kind']=='TRANSITION_INTENT']
    active_open=None
    for r in edges:
        if r['event']['transition_kind']=='opened': active_open=r
        elif r['event']['transition_kind']=='recovered': active_open=None
    if current['state']=='exited' and active_open is None and not any(r['kind']=='HELD' for r in records):
        seq=len(edges)+1; pred=edges[-1]['event']['transition_id'] if edges else None
        # A new host genesis is admitted only for an explicitly verified absent app stream.
        if not c.get('app_stream_absent_verified',False) and not edges:
            j.append('HELD',{'reason':'app-stream-genesis-not-proven','context':ctx}); return 3
        event=edge(c,j,'opened',current,seq=seq,pred=pred,generation=sum(1 for r in edges if r['event']['transition_kind']=='opened')+1)
        j.append('EPISODE_OPEN',{'transition_id':event['transition_id'],'context':ctx})
        state=read_json(c['observer_state']) or {}; active=read_json(c['active_file']) or {}
        identity=observer_identity(c)
        j.append('OUTAGE_BARRIER',{'transition_id':event['transition_id'],'loop_sequence':state.get('loop_sequence'),'observer_proc':identity,'boot_id':current.get('boot_id'),'timing_revision':active.get('revision'),'timing_digest':active.get('digest'),'outage_observed_epoch':time.time(),'monotonic_ns':time.monotonic_ns()})
        # Actual provider I/O occurs after the immutable intent is durable.
        send_provider(c,j,event)
        records=j._read()['records']; project_pending(c,j,records)
    if current['state']=='running' and active_open is not None:
        tid=active_open['event']['transition_id']
        barriers=[r for r in records if r['kind']=='OUTAGE_BARRIER' and r.get('transition_id')==tid]
        if not barriers:
            state=read_json(c['observer_state']) or {}; active=read_json(c['active_file']) or {}; identity=observer_identity(c)
            j.append('OUTAGE_BARRIER',{'transition_id':tid,'loop_sequence':state.get('loop_sequence'),'observer_proc':identity,'boot_id':current.get('boot_id'),'timing_revision':active.get('revision'),'timing_digest':active.get('digest'),'outage_observed_epoch':time.time(),'monotonic_ns':time.monotonic_ns()})
        else:
            barrier=barriers[-1]
            recovery_context=recovery_barrier(c,barrier)
            if recovery_context is not None:
                previous_recovery=[r for r in records if r['kind']=='RECOVERY_BARRIER' and r.get('transition_id')==tid]
                if not previous_recovery:
                    j.append('RECOVERY_BARRIER',{'transition_id':tid,**recovery_context})
                elif observer_recovery(c,previous_recovery[-1]):
                    seq=len(edges)+1; pred=edges[-1]['event']['transition_id'] if edges else None; opening=active_open['event']
                    recovered=edge(c,j,'recovered',current,first=opening['first_detected_at'],episode=opening['episode_id'],opening_id=opening['opening_transition_id'],seq=seq,pred=pred,generation=opening['episode_generation'])
                    send_provider(c,j,recovered); project_pending(c,j,j._read()['records'])
            # Missing or changed context remains unknown and cannot close the episode.
    return 0


def supervise_once(c):
    """Independent local supervisor; it never depends on sender health or alert transport."""
    health=Journal(c['health_journal']); history=health._read()['records']
    sender_pid=Path(c['journal']).with_suffix('.pid')
    prior=next((r.get('state') for r in reversed(history) if r.get('kind')=='SENDER_HEALTH_EDGE'),None)
    state='healthy'; reason=None
    try:
        pid=int(sender_pid.read_text().strip())
        os.kill(pid,0)
        Journal(c['journal'])._read()
    except FileNotFoundError:
        if prior is None:
            first=next((r for r in history if r.get('kind')=='SUPERVISOR_OBSERVATION'
                and r.get('state')=='starting'),None)
            age=(dt.datetime.now(UTC)-dt.datetime.fromisoformat(first['at'].replace('Z','+00:00'))).total_seconds() if first else 0
            state='dead' if first and age>=30 else 'starting'
            reason='sender_pid_missing' if state=='dead' else 'sender_startup_grace'
        else:
            state='dead'; reason='sender_pid_missing'
    except ProcessLookupError:
        state='dead'; reason='sender_process_missing'
    except Exception as exc:
        state='unhealthy'; reason='sender_journal_invalid' if type(exc).__name__=='RuntimeError' else 'sender_supervision_check_failed'
    if state in {'healthy','dead','unhealthy'} and state!=prior:
        health.append('SENDER_HEALTH_EDGE',{'state':state,'failure_code':reason,'actor':'independent_host_supervisor','deployment_id':c['deployment_id'],'subject_id':'host-sender:'+c['subject_id'],'producer_id':'g7-host-operational-alert-sender/v1','binding_revision':c['binding_revision'],'route_revision':c['route']['revision']})
    else:
        health.append('SUPERVISOR_OBSERVATION',{'state':state,'failure_code':reason,'actor':'independent_host_supervisor'})
    project_supervisor_health(c,health)
    return state

def main():
    p=argparse.ArgumentParser(); p.add_argument('--catalog',required=True); p.add_argument('--once',action='store_true'); p.add_argument('--supervise',action='store_true'); a=p.parse_args()
    c=load_catalog(a.catalog)
    if a.supervise:
        while True:
            supervise_once(c)
            if a.once: return 0
            time.sleep(min(c['freshness_seconds'],10))
    while True:
        try:
            pidfile=Path(c['journal']).with_suffix('.pid'); pidfile.parent.mkdir(mode=0o700,parents=True,exist_ok=True); pidfile.write_text(str(os.getpid()),encoding='ascii'); os.chmod(pidfile,0o600)
            rc=run_once(c)
        except Exception as exc:
            # Avoid recursive external delivery; caller's independent supervisor owns this fault.
            print(json.dumps({'sender':'unhealthy','failure_code':type(exc).__name__},separators=(',',':')),file=sys.stderr); return 2
        if a.once: return rc
        time.sleep(min(c['freshness_seconds'],60))
if __name__=='__main__': raise SystemExit(main())
