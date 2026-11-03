#!/usr/bin/env python3
"""Host-only durable G7 operational alert sender; never mounted into UVM."""
from __future__ import annotations
import argparse, datetime as dt, fcntl, hashlib, json, os, re, ssl, subprocess, sys, time, threading, urllib.error, urllib.request, uuid
from pathlib import Path
from contextlib import contextmanager
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

def parse_catalog(path):
    raw=Path(path).read_bytes(); c=json.loads(raw)
    required={'generation','deployment_id','subject_id','principal_id','producer_id','condition','binding_revision','container_id','image_id','deployment_label','run_label','recovery_epoch','observer_state','supervisor_state','observer_pidfile','active_file','scheduler_file','observer_readback','supervisor_readback','journal','health_journal','api_url','api_token_file','ca_file','route','retry_count','retry_age_seconds','freshness_seconds','request_deadline_seconds','app_stream_absent_verified'}
    if not isinstance(c,dict) or set(c)!=required or type(c['generation']) is not int or c['generation']<1: raise ValueError('catalog-shape-invalid')
    if c['condition'] not in {'container_availability','host_sender_health'}: raise ValueError('catalog-condition-invalid')
    if type(c['app_stream_absent_verified']) is not bool: raise ValueError('catalog-genesis-proof-invalid')
    api=urlparse(c['api_url']); route=c['route']
    route_fields={'enabled','revision','destination_ref','endpoint','channel_id','credential_file','mentions','installation_id','workspace_id','runbook_url'}
    provider=urlparse(route.get('endpoint','')) if isinstance(route,dict) else urlparse('')
    runbook=urlparse(route.get('runbook_url','')) if isinstance(route,dict) else urlparse('')
    endpoint=urlparse(route.get('endpoint','')) if isinstance(route,dict) else urlparse('')
    if (api.scheme not in {'http','https'} or api.hostname not in {'127.0.0.1','localhost','::1'}
            or not isinstance(route,dict) or set(route)!=route_fields
            or type(route.get('enabled')) is not bool or type(route.get('revision')) is not int
            or route['revision']<1 or not isinstance(route.get('destination_ref'),str) or not route['destination_ref']
            or provider.scheme!='https' or not provider.hostname or provider.username or provider.password
            or provider.query or provider.fragment or not isinstance(route.get('mentions'),list)
            or any(not isinstance(m,str) or re.fullmatch(r'U[A-Z0-9]{2,32}',m) is None for m in route['mentions'])
            or not isinstance(route.get('runbook_url'),str) or runbook.scheme!='https'
            or not runbook.hostname or runbook.username or runbook.password or runbook.query or runbook.fragment):
        raise ValueError('catalog-route-invalid')
    for k in ('binding_revision','retry_count','retry_age_seconds','freshness_seconds','request_deadline_seconds'):
        if type(c[k]) is not int or c[k] < (1 if k!='retry_count' else 0): raise ValueError('catalog-bound-invalid')
    if c['retry_count']>5 or c['retry_age_seconds']>300 or c['freshness_seconds']>86400 or c['request_deadline_seconds']>60:
        raise ValueError('catalog-bound-invalid')
    c['_path']=str(Path(path).resolve()); c['_digest']=sha(canonical(c)); return c

_HELD_LOCKS=threading.local()

@contextmanager
def stream_locks(c, purpose):
    """Aliases share inode-independent locks on both durable journal names.

    Lock order is owner -> authority -> individual journal; supervisor uses only
    authority/journal locks so it can observe a wedged owner.
    """
    paths=sorted({str(Path(c[key]).resolve()) for key in ('journal','health_journal')})
    if len(paths)!=2: raise ValueError('catalog-journals-must-be-distinct')
    lock_paths=[Path(path+'.'+purpose+'.lock') for path in paths]
    if purpose=='authority':lock_paths.append(Path(c['_path']).with_suffix('.lock'))
    descriptors=[]
    owned=getattr(_HELD_LOCKS,'paths',set()); _HELD_LOCKS.paths=owned
    try:
        for lock in sorted(set(lock_paths)):
            lock.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            if str(lock) in owned: continue
            fd=os.open(lock,os.O_RDWR|os.O_CREAT,0o600); descriptors.append((str(lock),fd))
            fcntl.flock(fd,fcntl.LOCK_EX); owned.add(str(lock))
        yield
    finally:
        for name,fd in reversed(descriptors):
            owned.remove(name); fcntl.flock(fd,fcntl.LOCK_UN); os.close(fd)


def reserve_catalog(c):
    # Each journal independently remembers its companion and authority high-water.
    # Reserve both before returning authority; partial writes only hold availability.
    pair={key:str(Path(c[key]).resolve()) for key in ('journal','health_journal')}
    binding_file=Path(c['_path']+'.journals')
    if binding_file.exists() and read_json(binding_file)!=pair:
        raise ValueError('catalog-journal-binding-changed')
    marks=[]
    for key in pair:
        path=Path(pair[key]+'.catalog-authority')
        old=read_json(path) if path.exists() else None
        if path.exists() and (not isinstance(old,dict) or set(old)!={'generation','catalog_path','journals','catalog_digest'}
                or type(old.get('generation')) is not int):
            raise ValueError('catalog-generation-highwater-invalid')
        if old and (old['journals']!=pair or old['catalog_path']!=c['_path']):
            raise ValueError('catalog-journal-binding-mismatch')
        if old and c['generation']<old['generation']: raise ValueError('catalog-generation-rollback')
        if old and c['generation']==old['generation'] and c['_digest']!=old['catalog_digest']:
            raise ValueError('catalog-generation-content-conflict')
        marks.append((path,old))
    generation_file=Path(c['_path']+'.generation')
    if generation_file.exists():
        highwater=read_json(generation_file)
        if type(highwater) is not int: raise ValueError('catalog-generation-highwater-invalid')
        if c['generation']<highwater: raise ValueError('catalog-generation-rollback')
    if not binding_file.exists():atomic(binding_file,canonical(pair)+b'\n')
    for path,old in marks:
        if old is None or old['generation']<c['generation']:
            atomic(path,canonical({'generation':c['generation'],'catalog_path':c['_path'],'journals':pair,'catalog_digest':c['_digest']})+b'\n')
    if not generation_file.exists() or read_json(generation_file)<c['generation']:
        atomic(generation_file,canonical(c['generation'])+b'\n')


def load_catalog(path, *, authority_locked=False):
    candidate=parse_catalog(path)
    def admit():
        current=parse_catalog(path)
        if any(Path(current[k]).resolve()!=Path(candidate[k]).resolve() for k in ('journal','health_journal')):
            raise ValueError('catalog-journal-binding-changed')
        reserve_catalog(current)
        return current
    if authority_locked: return admit()
    with stream_locks(candidate,'authority'): return admit()

class Journal:
    def __init__(self,path):
        self.path=Path(path); self.lock=self.path.with_suffix(self.path.suffix+'.lock')
        self.genesis=self.path.with_suffix(self.path.suffix+'.genesis')
    def _read(self):
        if not self.path.exists():
            if self.genesis.exists(): raise RuntimeError('journal-missing-after-genesis')
            return {'version':1,'sequence':0,'head':'0'*64,'records':[]}
        try: doc=json.loads(self.path.read_bytes())
        except Exception as exc: raise RuntimeError('journal-corrupt') from exc
        if (not isinstance(doc,dict) or set(doc)!={'version','sequence','head','records'}
                or type(doc.get('version')) is not int or doc['version']!=1
                or type(doc.get('sequence')) is not int or not isinstance(doc.get('records'),list)):
            raise RuntimeError('journal-corrupt')
        prev='0'*64
        for i,r in enumerate(doc['records'],1):
            if (not isinstance(r,dict) or type(r.get('sequence')) is not int
                    or r.get('sequence')!=i or r.get('previous_digest')!=prev):
                raise RuntimeError('journal-chain-invalid')
            digest=r.get('digest'); body={k:v for k,v in r.items() if k!='digest'}
            if digest!=sha(canonical(body)): raise RuntimeError('journal-digest-invalid')
            prev=digest
        if doc['sequence']!=len(doc['records']) or doc['head']!=prev: raise RuntimeError('journal-head-invalid')
        return doc
    def ensure_genesis(self, *, allow_empty=False, context=None):
        """Consume the one allowed genesis proof and reject later journal loss."""
        self.lock.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        fd=os.open(self.lock,os.O_RDWR|os.O_CREAT,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            if self.genesis.exists():
                if not self.path.exists(): raise RuntimeError('journal-missing-after-genesis')
                marker=json.loads(self.genesis.read_bytes())
                if (not isinstance(marker,dict) or marker.get('version')!=1
                        or marker.get('journal_id') is None): raise RuntimeError('journal-genesis-invalid')
                return self._read()
            if self.path.exists():
                doc=self._read(); journal_id=str(uuid.uuid4())
                marker={'version':1,'journal_id':journal_id,'initial_head':doc['head'],
                    'genesis_kind':'existing-journal-adopted','context_digest':sha(canonical(context or {}))}
                atomic(self.genesis,canonical(marker)+b'\n')
                return doc
            if not allow_empty: raise RuntimeError('journal-genesis-proof-required')
            journal_id=str(uuid.uuid4())
            body={'sequence':1,'previous_digest':'0'*64,'at':stamp(),'kind':'GENESIS',
                'journal_id':journal_id,'context_digest':sha(canonical(context or {}))}
            body['digest']=sha(canonical(body))
            doc={'version':1,'sequence':1,'head':body['digest'],'records':[body]}
            marker={'version':1,'journal_id':journal_id,'initial_head':body['digest'],
                'genesis_kind':'consumed-app-stream-proof','context_digest':body['context_digest']}
            atomic(self.genesis,canonical(marker)+b'\n')
            atomic(self.path,canonical(doc)+b'\n')
            return doc
        finally:
            fcntl.flock(fd,fcntl.LOCK_UN); os.close(fd)
    def append(self,kind,fields):
        return self.append_many([(kind,fields)])[-1]

    def append_many(self, entries):
        """Publish an admission's intent and SENDING in one durable replacement."""
        self.lock.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        fd=os.open(self.lock,os.O_RDWR|os.O_CREAT,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX); doc=self._read(); added=[]
            for kind,fields in entries:
                body={'sequence':doc['sequence']+1,'previous_digest':doc['head'],
                    'at':stamp(),'kind':kind,**fields}
                body['digest']=sha(canonical(body)); doc['records'].append(body)
                doc['sequence']=body['sequence']; doc['head']=body['digest']; added.append(body)
            atomic(self.path,canonical(doc)+b'\n')
            return added
        finally: fcntl.flock(fd,fcntl.LOCK_UN); os.close(fd)


def inspect_target(c):
    # The only Docker operation this process can invoke is inspect for one configured ID.
    call_started=time.time(); mono_started=time.monotonic_ns()
    p=subprocess.run(['docker','inspect','--type','container',c['container_id']],capture_output=True,text=True,timeout=8,check=False)
    call_ended=time.time(); mono_ended=time.monotonic_ns()
    if p.returncode: return {'state':'unknown','reason':'inspect-unavailable'}
    try: data=json.loads(p.stdout)
    except Exception: return {'state':'unknown','reason':'inspect-malformed'}
    if not isinstance(data,list) or len(data)!=1: return {'state':'unknown','reason':'inspect-identity'}
    x=data[0]
    if not isinstance(x,dict) or not isinstance(x.get('Config'),dict) or not isinstance(x.get('State'),dict):
        return {'state':'unknown','reason':'inspect-state-shape-or-time-invalid'}
    labels=x['Config'].get('Labels') or {}; state=x['State']
    if not isinstance(labels,dict): return {'state':'unknown','reason':'inspect-identity'}
    identity=(x.get('Id')==c['container_id'] and x.get('Image')==c['image_id'] and labels.get('uvm.deployment_id')==c['deployment_label'] and labels.get('uvm.run_id')==c['run_label'])
    if not identity: return {'state':'unknown','reason':'target-context-changed'}
    status=state.get('Status'); running=state.get('Running'); paused=state.get('Paused')
    started=state.get('StartedAt'); finished=state.get('FinishedAt')
    def parse_docker_time(value):
        if not isinstance(value,str) or re.fullmatch(r'0001-01-01T00:00:00(?:\.0{1,9})?Z',value): return None
        try:
            parsed=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
            return parsed.timestamp() if parsed.tzinfo is not None else None
        except Exception: return None
    started_epoch=parse_docker_time(started); finished_epoch=parse_docker_time(finished)
    now=call_ended
    finished_is_zero=isinstance(finished,str) and re.fullmatch(r'0001-01-01T00:00:00(?:\.0{1,9})?Z',finished) is not None
    if (type(running) is not bool or type(paused) is not bool or call_ended<call_started
            or abs((call_ended-call_started)-(mono_ended-mono_started)/1e9)>1
            or call_ended-call_started>10
            or (status in {'running','exited'} and (started_epoch is None or started_epoch>now+OBSERVER_MAX_FUTURE_SKEW_SECONDS))
            or (status=='running' and (running is not True or paused is not False or started_epoch is None or started_epoch>now+OBSERVER_MAX_FUTURE_SKEW_SECONDS))
            or (status=='running' and ((finished_epoch is None and not finished_is_zero)
                or (finished_epoch is not None and finished_epoch>started_epoch)))
            or (status=='exited' and (running is not False or paused is not False or finished_epoch is None
                or finished_epoch>now+OBSERVER_MAX_FUTURE_SKEW_SECONDS or finished_epoch<started_epoch))
            or (status=='paused' and (running is not True or paused is not True))
            or (status=='restarting' and running is not True)):
        return {'state':'unknown','reason':'inspect-state-shape-or-time-invalid'}
    mapped={'running':'running','exited':'exited','created':'unknown','restarting':'unknown','paused':'unknown','dead':'unknown'}
    return {'state':mapped.get(status,'unknown'),'started_at':started,'started_epoch':started_epoch,
        'finished_at':finished,'finished_epoch':finished_epoch,'inspect_started_epoch':call_started,
        'inspect_ended_epoch':call_ended,'inspect_started_monotonic_ns':mono_started,
        'inspect_ended_monotonic_ns':mono_ended,'container_id':x.get('Id'),'image_id':x.get('Image'),
        'deployment_label':labels.get('uvm.deployment_id'),'run_label':labels.get('uvm.run_id'),
        'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}

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
    """Reserve authority before publishing a catalog under dispatch's stable lock."""
    path=Path(path)
    candidate_path=path.with_name(path.name+'.candidate-'+uuid.uuid4().hex)
    atomic(candidate_path,canonical(document)+b'\n')
    try: candidate=parse_catalog(candidate_path)
    finally: candidate_path.unlink()
    current=parse_catalog(path)
    if any(Path(candidate[k]).resolve()!=Path(current[k]).resolve() for k in ('journal','health_journal')):
        raise ValueError('catalog-journal-binding-changed')
    with stream_locks(current,'authority'):
        current=load_catalog(path,authority_locked=True)
        if candidate['generation']<=current['generation']:
            raise ValueError('catalog-generation-must-increase')
        if candidate['route']!=current['route'] and candidate['route']['revision']<=current['route']['revision']:
            raise ValueError('catalog-route-revision-must-increase')
        candidate['_path']=current['_path']
        candidate['_digest']=sha(canonical({k:v for k,v in candidate.items() if k!='_digest'}))
        reserve_catalog(candidate)
        atomic(path,canonical(document)+b'\n')
        return load_catalog(path,authority_locked=True)


def delivery_body(event, route):
    text=(f"{event['condition']}: deployment health changed ({event['transition_kind']}). "
        f"Incident {event['episode_id']} at {event['observed_at']}. Runbook: {route['runbook_url']}")
    if route['mentions']:
        text += " " + " ".join("<@"+m+">" for m in route['mentions'])
    return {'channel':route['channel_id'],'text':text,'metadata':{'event_type':'uvm_g7_operational_alert','event_payload':{'condition':event['condition'],'incident_id':event['episode_id'],'transition_kind':event['transition_kind'],'observed_at':event['observed_at']}}}


def send_provider(c,j,event,inspection=None):
    """One durable-stream owner through admission/outcome, authority released for I/O."""
    with stream_locks(c,'sender-owner'):
        return _send_provider_locked(c,j,event,inspection)


def _send_provider_locked(c,j,event,inspection=None):
    request_body=delivery_body(event,c['route']); tid=event['transition_id']
    before_epoch=time.time(); before_mono=time.monotonic_ns()
    before_boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    retry_after=None
    with stream_locks(c,'authority'):
        current=load_catalog(c['_path'],authority_locked=True)
        if current['_digest']!=c['_digest'] or current['route']!=c['route']:
            j.append('HELD',{'reason':'catalog-or-route-changed-before-dispatch','transition_id':tid}); return None
        records=j._read()['records']
        health=event.get('condition')=='host_sender_health'
        fresh=None if health else inspect_target(c)
        context=health_context(c) if health else bound_context(c,fresh)
        if context_fenced(j,context,{'HEALTH_TRANSITION_INTENT','SENDER_HEALTH_EDGE'} if health else {'TRANSITION_INTENT'}): return None
        intents=[r for r in records if r.get('kind') in {'TRANSITION_INTENT','HEALTH_TRANSITION_INTENT'}]
        intent=next((r for r in intents if r.get('transition_id')==tid),None)
        outcomes=[r for r in records if r.get('kind')=='ATTEMPT_OUTCOME' and r.get('transition_id')==tid]
        if outcomes and (outcomes[-1]['attempt']['outcome'] in {'accepted','uncertain'}
                or outcomes[-1]['attempt'].get('failure_detail')!='rate_limited'): return outcomes[-1]['attempt']
        schedules=[r for r in records if r.get('kind')=='RETRY_SCHEDULE' and r.get('transition_id')==tid]
        consumed={r.get('schedule_sequence') for r in records if r.get('kind') in {'RETRY_CONSUMED','RETRY_EXPIRED','RETRY_SUPERSEDED'}}
        later=[r['event'] for r in intents if r['event'].get('episode_id')==event.get('episode_id')
            and r['event'].get('transition_kind')=='recovered' and r.get('transition_id')!=tid]
        if outcomes and not schedules: return outcomes[-1]['attempt']
        if schedules:
            schedule=schedules[-1]
            if schedule['sequence'] in consumed: return None
            if event['transition_kind']=='opened' and later:
                j.append('RETRY_SUPERSEDED',{'transition_id':tid,'schedule_sequence':schedule['sequence'],
                    'by_transition_id':later[-1]['transition_id']}); return None
            if time.time()<schedule['due_epoch']: return None
            if time.time()>schedule['deadline_epoch'] or len(outcomes)>=c['retry_count']+1:
                j.append('RETRY_EXPIRED',{'transition_id':tid,'schedule_sequence':schedule['sequence']}); return None
        now_epoch=time.time(); now_mono=time.monotonic_ns()
        try:
            observed=dt.datetime.fromisoformat(event['observed_at'].replace('Z','+00:00')).timestamp()
            attempted_at=stamp(); attempted_epoch=dt.datetime.fromisoformat(attempted_at.replace('Z','+00:00')).timestamp()
            last_attempt=max((dt.datetime.fromisoformat(r['attempt']['attempted_at'].replace('Z','+00:00')).timestamp() for r in outcomes),default=0)
            clock_ok=(now_mono>=before_mono and abs(now_epoch-before_epoch-(now_mono-before_mono)/1e9)<=1
                and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==before_boot
                and observed<=attempted_epoch and attempted_epoch>last_attempt
                and abs(attempted_epoch-now_epoch)<=1)
            prior_clock=next((r for r in reversed(records) if r.get('kind') in {'SENDING','INSPECTION'}
                and type(r.get('clock_monotonic_ns')) is int),None)
            if prior_clock:
                clock_ok=clock_ok and prior_clock['clock_boot_id']==before_boot and now_mono>=prior_clock['clock_monotonic_ns'] and abs(now_epoch-prior_clock['clock_epoch']-(now_mono-prior_clock['clock_monotonic_ns'])/1e9)<=1
        except (KeyError,TypeError,ValueError,OverflowError): clock_ok=False
        if not clock_ok:
            j.append('HELD',{'reason':'dispatch-clock-continuity-invalid','transition_id':tid}); return None
        if not health:
            expected='exited' if event['transition_kind']=='opened' else 'running'
            recent=(type(fresh.get('inspect_ended_epoch')) in (int,float)
                and 0<=now_epoch-fresh['inspect_ended_epoch']<=min(10,c['freshness_seconds']))
            same=(inspection is None or (bound_context(c,inspection)==context
                and inspection.get('started_at')==fresh.get('started_at')
                and type(inspection.get('inspect_ended_epoch')) in (int,float)
                and 0<=now_epoch-inspection['inspect_ended_epoch']<=min(10,c['freshness_seconds'])))
            if not recent or not same or fresh.get('state')!=expected:
                j.append('CANCELED_BEFORE_SUBMISSION' if intent is None else 'DISPATCH_SUPPRESSED',
                    {'transition_id':tid,'reason':'target-no-longer-qualifies','context':context})
                return None
            if event['transition_kind']=='recovered':
                barrier=next((r for r in reversed(records) if r.get('kind')=='RECOVERY_BARRIER'
                    and r.get('transition_id')==event.get('opening_transition_id')),None)
                if not barrier or not observer_recovery(c,barrier,j): return None
        route=current_route(current); credential=Path(route['credential_file']).read_text().strip()
        admission=[]
        if intent is None:
            # No API sequence is allocated for a candidate canceled before SENDING.
            if not set(event)=={'schema_version','deployment_id','subject_id','condition','transition_id',
                    'transition_sequence','predecessor_id','episode_id','opening_transition_id','episode_generation',
                    'transition_kind','configuration_revision','first_detected_at','observed_at','recovered_at','evidence_refs','producer_id'}:
                raise ValueError('dispatch-requires-complete-transition')
            expected_seq=len(intents)+1
            if event['transition_sequence']!=expected_seq or event['predecessor_id']!=(intents[-1]['transition_id'] if intents else None):
                raise ValueError('dispatch-stream-head-changed')
            admission.append(('TRANSITION_INTENT',{'transition_id':tid,'api_sequence':expected_seq,
                'payload_digest':sha(canonical(event)),'event':event,'context':context}))
        attempt={'schema_version':1,'attempt_id':str(uuid.uuid4()),'outcome':'uncertain',
            'attempted_at':attempted_at,'receipt_ref':None,'failure_detail':'submission_uncertain'}
        admission.append(('SENDING',{'transition_id':tid,'attempt':attempt,
            'route_revision':route['revision'],'route_digest':sha(canonical(route)),
            'catalog_generation':c['generation'],'catalog_digest':c['_digest'],
            'request_digest':sha(canonical(request_body)),
            'started_monotonic_ns':now_mono,'boot_id':before_boot,'started_epoch':now_epoch,
            'clock_monotonic_ns':now_mono,'clock_epoch':now_epoch,'clock_boot_id':before_boot,
            'target_started_at':fresh.get('started_at') if fresh else None,
            'target_boot_id':fresh.get('boot_id') if fresh else None,
            'target_inspect_ended_epoch':fresh.get('inspect_ended_epoch') if fresh else None,
            'work_deadline_monotonic_ns':now_mono+int(c['request_deadline_seconds']*1_000_000_000)}))
        sending=j.append_many(admission)[-1]
        if event['transition_kind']=='recovered':
            opening_ids={r['transition_id'] for r in intents if r['event'].get('episode_id')==event['episode_id']
                and r['event'].get('transition_kind')=='opened'}
            for queued in records:
                if queued.get('kind')=='RETRY_SCHEDULE' and queued.get('transition_id') in opening_ids and queued['sequence'] not in consumed:
                    j.append('RETRY_SUPERSEDED',{'transition_id':queued['transition_id'],
                        'schedule_sequence':queued['sequence'],'by_transition_id':tid})
        if schedules:
            j.append('RETRY_CONSUMED',{'transition_id':tid,'schedule_sequence':schedules[-1]['sequence'],'attempt_id':attempt['attempt_id']})
    try:
        status,response=post_json(route['endpoint'],credential,request_body,ca_file=c['ca_file'],timeout=c['request_deadline_seconds'])
        if (200<=status<300 and isinstance(response,dict) and response.get('ok') is True
                and response.get('channel')==route['channel_id'] and isinstance(response.get('ts'),str)
                and re.fullmatch(r'[A-Za-z0-9._:-]{1,200}',response['ts'])):
            attempt.update(outcome='accepted',receipt_ref='provider:'+response['ts'],failure_detail=None)
        elif status==429: attempt.update(outcome='failed',failure_detail='rate_limited')
        elif 400<=status<500: attempt.update(outcome='failed',failure_detail='provider_rejected')
        else: attempt.update(outcome='uncertain',failure_detail='response_invalid')
    except urllib.error.HTTPError as exc:
        if exc.code==429:
            attempt.update(outcome='failed',failure_detail='rate_limited')
            raw_delay=exc.headers.get('Retry-After','') if exc.headers else ''
            if re.fullmatch(r'[0-9]{1,4}',raw_delay): retry_after=min(int(raw_delay),30)
        elif exc.code in {400,401,403,404,422}: attempt.update(outcome='failed',failure_detail='provider_rejected')
        else: attempt.update(outcome='uncertain',failure_detail='submission_uncertain')
    except (urllib.error.URLError,TimeoutError,ConnectionError,ssl.SSLError):
        attempt.update(outcome='uncertain',failure_detail='submission_uncertain')
    j.append('ATTEMPT_OUTCOME',{'transition_id':tid,'attempt':attempt,'outcome_completed_at':stamp()})
    if attempt['outcome']=='failed' and attempt['failure_detail']=='rate_limited' and len(outcomes)+1<c['retry_count']+1 and retry_after is not None:
        first_epoch=sending.get('started_epoch',time.time())
        if schedules: first_epoch=schedules[0].get('first_attempt_epoch',first_epoch)
        deadline=first_epoch+c['retry_age_seconds']
        due=time.time()+retry_after
        if due<=deadline:
            j.append('RETRY_SCHEDULE',{'transition_id':tid,'due_epoch':due,'deadline_epoch':deadline,
                'first_attempt_epoch':first_epoch,'retry_after_seconds':retry_after,
                'attempt_number':len(outcomes)+1,'request_digest':sha(canonical(request_body)),
                'target_started_at':sending.get('target_started_at'),
                'target_boot_id':sending.get('target_boot_id'),
                'target_inspect_ended_epoch':sending.get('target_inspect_ended_epoch')})
    return attempt


def project_pending(c,j,records):
    with stream_locks(c,'authority'):
        return _project_pending_locked(c,j,records)


def _project_pending_locked(c,j,records):
    if load_catalog(c['_path'],authority_locked=True)['_digest']!=c['_digest']:
        j.append('HELD',{'reason':'catalog-or-route-changed-before-projection'}); return
    expected=health_context(c) if Path(j.path).resolve()==Path(c['health_journal']).resolve() else bound_context(c,inspect_target(c))
    kinds={'HEALTH_TRANSITION_INTENT','SENDER_HEALTH_EDGE'} if expected['condition']=='host_sender_health' else {'TRANSITION_INTENT'}
    if context_fenced(j,expected,kinds): return
    for record in records:
        if record['kind'] not in {'TRANSITION_INTENT','HEALTH_TRANSITION_INTENT'}: continue
        event=record['event']; tid=event['transition_id']
        if not any(r.get('kind')=='ATTEMPT_OUTCOME' and r.get('transition_id')==tid for r in records): return
        ack_kind='HEALTH_TRANSITION_ACK' if record['kind']=='HEALTH_TRANSITION_INTENT' else 'TRANSITION_ACK'
        transition_ack=any(r['kind']==ack_kind and r.get('transition_id')==tid for r in records)
        if not transition_ack:
            try: status,response=api_post(c,'/api/v1/integrations/incidents',event)
            except Exception: return
            digest=sha(canonical(event))
            if status not in (200,201) or not ack_transition(response,event,digest): return
            j.append(ack_kind,{'transition_id':tid,'ack':response})
            records.append(j._read()['records'][-1])
        attempts=[r['attempt'] for r in records if r['kind']=='ATTEMPT_OUTCOME' and r.get('transition_id')==tid]
        for attempt in attempts:
            already=any(r['kind']=='ATTEMPT_ACK' and r.get('attempt_id')==attempt['attempt_id'] for r in records)
            if already: continue
            try: status,response=api_post(c,f"/api/v1/integrations/incidents/{tid}/delivery",attempt)
            except Exception: return
            replay=(isinstance(response,dict) and type(response.get('idempotent')) is bool
                and response['idempotent'] is True)
            if status not in (200,201) or not ack_attempt(response,tid,attempt,replay=replay): return
            j.append('ATTEMPT_ACK',{'transition_id':tid,'attempt_id':attempt['attempt_id'],'ack':response})
            records.append(j._read()['records'][-1])


def dispatch_scheduled_retries(c,j,current,context,records):
    """Admit at most one persisted retry after rechecking its exact episode context."""
    consumed={r.get('schedule_sequence') for r in records if r.get('kind')=='RETRY_CONSUMED'}
    consumed|={r.get('schedule_sequence') for r in records if r.get('kind')=='RETRY_EXPIRED'}
    consumed|={r.get('schedule_sequence') for r in records if r.get('kind')=='RETRY_SUPERSEDED'}
    intents={r.get('transition_id'):r for r in records if r.get('kind')=='TRANSITION_INTENT'}
    for schedule in records:
        if schedule.get('kind')!='RETRY_SCHEDULE' or schedule.get('sequence') in consumed: continue
        tid=schedule.get('transition_id'); intent=intents.get(tid)
        if not intent or time.time()<schedule.get('due_epoch',float('inf')): continue
        event=intent['event']; kind=event['transition_kind']
        if time.time()>schedule.get('deadline_epoch',0):
            j.append('RETRY_EXPIRED',{'transition_id':tid,'schedule_sequence':schedule['sequence']}); continue
        later=[r['event'] for r in records if r.get('kind')=='TRANSITION_INTENT'
            and r.get('event',{}).get('episode_id')==event['episode_id']
            and r.get('event',{}).get('transition_sequence',0)>event['transition_sequence']]
        if kind=='opened' and any(x['transition_kind']=='recovered' for x in later):
            j.append('RETRY_SUPERSEDED',{'transition_id':tid,'schedule_sequence':schedule['sequence'],
                'by_transition_id':next(x['transition_id'] for x in later if x['transition_kind']=='recovered')}); continue
        expected='exited' if kind=='opened' else 'running'
        if (current.get('state')!=expected or intent.get('context')!=context
                or current.get('started_at')!=schedule.get('target_started_at')
                or current.get('boot_id')!=schedule.get('target_boot_id')
                or type(current.get('inspect_ended_epoch')) not in (int,float)
                or time.time()-current['inspect_ended_epoch']>10):
            continue
        # A retry is admitted only while the original inspector and source context
        # remain current; send_provider rechecks route/catalog under its own lock.
        send_provider(c,j,event,current)
        records=j._read()['records']

def ack_transition(response,event,digest):
    keys={'schema_version','status','transition_id','transition_sequence','episode_id','episode_generation','payload_digest'}
    return (isinstance(response,dict) and set(response)==keys
        and type(response.get('schema_version')) is int and response.get('schema_version')==1
        and type(response.get('transition_sequence')) is int
        and type(response.get('episode_generation')) is int
        and response=={'schema_version':1,'status':'projected','transition_id':event['transition_id'],'transition_sequence':event['transition_sequence'],'episode_id':event['episode_id'],'episode_generation':event['episode_generation'],'payload_digest':digest})
def ack_attempt(response, transition, attempt, replay=False):
    keys={'schema_version','status','transition_id','attempt_id','outcome','idempotent'} | (set() if replay else {'superseded'})
    return isinstance(response,dict) and set(response)==keys and type(response.get('schema_version')) is int and response.get('schema_version')==1 and response.get('status')=='projected' and response.get('transition_id')==transition and response.get('attempt_id')==attempt['attempt_id'] and response.get('outcome')==attempt['outcome'] and response.get('idempotent') is replay and (replay or response.get('superseded') is False)

def _observer_recovery(c, previous):
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
        if stat[21]!=proc['start_ticks'] or stat[2] in {'Z','X'}: return False
    except Exception: return False
    supervisor=read_json(c['supervisor_state']) or {}; active=read_json(c['active_file']) or {}
    scheduler=read_json(c['scheduler_file']) or {}
    def fresh_readback(path):
        row=read_json(path) or {}
        try: age=(time.time()-dt.datetime.fromisoformat(row['observed_at'].replace('Z','+00:00')).timestamp())
        except Exception: return False
        return 0<=age<=c['freshness_seconds'] and row.get('revision')==previous.get('timing_revision') and row.get('digest')==previous.get('timing_digest')
    started_at=current_started(c)
    if started_at!=previous.get('started_at'): return False
    started=dt.datetime.fromisoformat(started_at.replace('Z','+00:00')).timestamp()
    floor=max(previous.get('barrier_completed_epoch',0),started)
    skew=previous.get('future_skew_seconds')
    if type(skew) is not int or not 0<=skew<=3600: return False
    now=time.time()
    try:
        completed_epoch=done.timestamp(); checked_epoch=at.timestamp()
        supervisor_epoch=dt.datetime.fromisoformat(supervisor['last_completed_loop_at'].replace('Z','+00:00')).timestamp()
        scheduler_epoch=dt.datetime.fromisoformat(scheduler['completed_at'].replace('Z','+00:00')).timestamp()
    except (KeyError,TypeError,ValueError): return False
    if not (0<=now-completed_epoch<=c['freshness_seconds']
            and checked_epoch<=completed_epoch and 0<=now-supervisor_epoch<=c['freshness_seconds']
            and 0<=now-scheduler_epoch<=c['freshness_seconds']): return False
    return (seq>previous.get('loop_sequence',0) and causal_sample(completed,floor,future_skew_seconds=skew) and causal_sample(last['at'],floor,future_skew_seconds=skew) and last.get('http_status')==200 and last.get('error') is None and (last.get('anchor_export') or {}).get('status') in {'healthy','late'} and (last.get('incident_projection') or {}).get('status') in {'healthy','late'} and (state.get('scheduler') or {}).get('status')=='healthy' and type(scheduler.get('loop_sequence')) is int and scheduler.get('boot_id')==previous.get('boot_id') and state.get('active_revision')==previous.get('timing_revision') and state.get('active_digest')==previous.get('timing_digest') and active.get('revision')==previous.get('timing_revision') and active.get('digest')==previous.get('timing_digest') and (supervisor.get('supervision') or {}).get('status')=='healthy' and fresh_readback(c['observer_readback']) and fresh_readback(c['supervisor_readback']) and time.monotonic_ns()>previous.get('monotonic_ns',0))


def recovery_read_context(c):
    inspected=inspect_target(c)
    identity=observer_identity(c)
    active=read_json(c['active_file']) or {}
    if inspected.get('state')!='running' or not identity: return None
    return {'target_context':bound_context(c,inspected),'started_at':inspected.get('started_at'),
        'observer_proc':identity,'boot_id':inspected.get('boot_id'),
        'timing_revision':active.get('revision'),'timing_digest':active.get('digest')}


def bracket_recovery(c, previous, read, journal=None):
    start_epoch=time.time(); start_mono=time.monotonic_ns()
    before=recovery_read_context(c)
    expected_started=previous.get('started_at',previous.get('target_started_at'))
    valid=(before is not None and before['started_at']==expected_started
        and all(before[k]==previous.get(k) for k in ('observer_proc','boot_id','timing_revision','timing_digest'))
        and type(previous.get('monotonic_ns')) is int and start_mono>=previous['monotonic_ns'])
    result=read() if valid else None
    after=recovery_read_context(c)
    end_epoch=time.time(); end_mono=time.monotonic_ns()
    stable=(valid and before==after and end_mono>=start_mono
        and abs(end_epoch-start_epoch-(end_mono-start_mono)/1e9)<=1
        and end_epoch-start_epoch<=min(10,c['freshness_seconds']))
    if journal is not None:
        journal.append('RECOVERY_READ',{'read_started_epoch':start_epoch,'read_ended_epoch':end_epoch,
            'read_started_monotonic_ns':start_mono,'read_ended_monotonic_ns':end_mono,
            'before':before,'after':after,'stable':bool(stable),'qualified':bool(stable and result)})
    return result if stable else None


def observer_recovery(c, previous, journal=None):
    return bool(bracket_recovery(c,previous,lambda:_observer_recovery(c,previous),journal))


def recovery_barrier(c, prior, journal=None):
    return bracket_recovery(c,prior,lambda:_recovery_barrier(c,prior),journal)


def current_started(c):
    inspected=inspect_target(c)
    if inspected.get('state')!='running' or not inspected.get('started_at'): raise ValueError('restart-identity-unavailable')
    return inspected['started_at']


def observer_identity(c):
    try:
        pid=int(Path(c['observer_pidfile']).read_text().strip())
        fields=Path(f'/proc/{pid}/stat').read_text().split()
        if fields[2] in {'Z','X'}: return None
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


def _recovery_barrier(c, prior):
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
            or identity!=prior.get('observer_proc') or ctx.get('boot_id')!=prior.get('boot_id')
            or ctx.get('started_at')!=prior.get('target_started_at')): return None
    if (type(active.get('revision')) is not int or not isinstance(active.get('digest'),str)
            or active.get('revision')!=prior.get('timing_revision')
            or active.get('digest')!=prior.get('timing_digest')): return None
    return {'loop_sequence':seq,'barrier_completed_epoch':done.timestamp(),'observer_proc':identity,'boot_id':ctx['boot_id'],'timing_revision':active['revision'],'timing_digest':active['digest'],'future_skew_seconds':skew,'monotonic_ns':time.monotonic_ns(),'started_at':ctx['started_at']}

def edge(c,j,kind,inspection,first=None,episode=None,opening_id=None,seq=1,pred=None,generation=1,persist=True):
    now=stamp(); tid=str(uuid.uuid4()); ep=episode or str(uuid.uuid4())
    opening_id=tid if kind=='opened' else opening_id
    event={'schema_version':1,'deployment_id':c['deployment_id'],'subject_id':c['subject_id'],'condition':c['condition'],'transition_id':tid,'transition_sequence':seq,'predecessor_id':pred,'episode_id':ep,'opening_transition_id':opening_id,'episode_generation':generation,'transition_kind':kind,'configuration_revision':c['binding_revision'],'first_detected_at':first or now,'observed_at':now,'recovered_at':now if kind=='recovered' else None,'evidence_refs':['host-inspection:'+sha(canonical(inspection))[:24]],'producer_id':c['producer_id']}
    if persist: j.append('TRANSITION_INTENT',{'transition_id':tid,'api_sequence':seq,'payload_digest':sha(canonical(event)),'event':event,'context':bound_context(c,inspection)})
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


def health_context(c):
    # Configured exact target identity, independent of Docker availability/main log.
    inspected={'container_id':c['container_id'],'image_id':c['image_id'],
        'deployment_label':c['deployment_label'],'run_label':c['run_label'],
        'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    return dict(bound_context(c,inspected),subject_id=f"host-sender:{c['deployment_id']}:{c['run_label']}",
        condition='host_sender_health')


def context_fenced(j, context, kinds):
    records=j._read()['records']
    reconciled={r.get('held_sequence') for r in records if r.get('kind')=='HELD_RECONCILIATION'}
    if any(r.get('kind')=='HELD' and r['sequence'] not in reconciled for r in records): return True
    for record in records:
        if record.get('kind') not in kinds: continue
        original=record.get('context')
        accepted=any(r.get('kind')=='HELD_RECONCILIATION'
            and r.get('prior_context_digest')==sha(canonical(original or {}))
            and r.get('restored_context_digest')==sha(canonical(context)) for r in records)
        if original!=context and not accepted:
            j.append('HELD',{'reason':'bound-service-context-changed','prior_context':original,'context':context})
            return True
    return False


def process_health_stream(c, health):
    """Resumed trusted sender dispatches and projects supervisor-recorded health edges."""
    if load_catalog(c['_path'])['_digest']!=c['_digest']:
        health.append('HELD',{'reason':'catalog-or-route-changed-before-dispatch'}); return 3
    ctx=health_context(c)
    if context_fenced(health,ctx,{'SENDER_HEALTH_EDGE','HEALTH_TRANSITION_INTENT'}): return 3
    records=health._read()['records']
    intents=[r for r in records if r.get('kind')=='HEALTH_TRANSITION_INTENT']
    consumed={r.get('health_edge_sequence') for r in intents}
    consumed|={r.get('health_edge_sequence') for r in records if r.get('kind')=='HEALTH_EDGE_IGNORED'}
    active=None; sequence=0; predecessor=None; generation=0
    for intent in intents:
        event=intent['event']; sequence=max(sequence,event['transition_sequence'])
        predecessor=event['transition_id']
        if event['transition_kind']=='opened': active=event; generation=event['episode_generation']
        elif event['transition_kind']=='recovered': active=None
    for health_edge in (r for r in records if r.get('kind')=='SENDER_HEALTH_EDGE'):
        if health_edge['sequence'] in consumed: continue
        state=health_edge.get('state'); edge_at=health_edge.get('at')
        if not isinstance(edge_at,str): continue
        if state in {'dead','unhealthy'} and active is None:
            kind='opened'; sequence+=1; generation+=1; tid=str(uuid.uuid4())
            episode=str(uuid.uuid4()); opening=tid; first=edge_at; recovered=None
            active={'episode_id':episode,'opening_transition_id':opening,
                'first_detected_at':first,'episode_generation':generation}
        elif state=='healthy' and active is not None:
            kind='recovered'; sequence+=1; tid=str(uuid.uuid4())
            episode=active['episode_id']; opening=active['opening_transition_id']
            first=active['first_detected_at']; generation=active['episode_generation']; recovered=edge_at
            active=None
        else:
            health.append('HEALTH_EDGE_IGNORED',{'health_edge_sequence':health_edge['sequence'],
                'state':state,'at':edge_at,'reason':'no-active-health-episode'})
            consumed.add(health_edge['sequence']); continue
        event={'schema_version':1,'deployment_id':c['deployment_id'],
            'subject_id':f"host-sender:{c['deployment_id']}:{c['run_label']}",
            'condition':'host_sender_health','transition_id':tid,'transition_sequence':sequence,
            'predecessor_id':predecessor,'episode_id':episode,'opening_transition_id':opening,
            'episode_generation':generation,'transition_kind':kind,
            'configuration_revision':c['binding_revision'],'first_detected_at':first,
            'observed_at':recovered or edge_at,'recovered_at':recovered,
            'evidence_refs':['host-supervisor:'+health_edge['digest'][:24]],
            'producer_id':c['producer_id']}
        health.append('HEALTH_TRANSITION_INTENT',{'transition_id':tid,
            'health_edge_sequence':health_edge['sequence'],'event':event,
            'context':ctx,'actor':'resumed_host_sender','binding_revision':c['binding_revision'],
            'route_revision':c['route']['revision'],'health_journal_head':health_edge['digest']})
        predecessor=tid; consumed.add(health_edge['sequence'])
        records=health._read()['records']
    intents=[r for r in records if r.get('kind')=='HEALTH_TRANSITION_INTENT']
    for intent in intents:
        event=intent['event']; tid=event['transition_id']
        outcomes=[r for r in records if r.get('kind')=='ATTEMPT_OUTCOME' and r.get('transition_id')==tid]
        if not outcomes or (outcomes[-1]['attempt'].get('failure_detail')=='rate_limited'
                and any(r.get('kind')=='RETRY_SCHEDULE' and r.get('transition_id')==tid
                    and r.get('sequence') not in {x.get('schedule_sequence') for x in records
                        if x.get('kind') in {'RETRY_CONSUMED','RETRY_EXPIRED','RETRY_SUPERSEDED'}}
                    for r in records)):
            send_provider(c,health,event)
            records=health._read()['records']
        project_pending(c,health,records)
        records=health._read()['records']


def health_only_once(c):
    """Restricted sender path: recover its independent health stream if main journal is corrupt."""
    with stream_locks(c,'sender-owner'):
        health=Journal(c['health_journal'])
        health.ensure_genesis(allow_empty=True,context={'deployment_id':c['deployment_id'],
            'subject_id':f"host-sender:{c['deployment_id']}:{c['run_label']}"})
        record_interrupted_sends(health,health._read()['records'])
        process_health_stream(c,health)


def _run_once_locked(c):
    j=Journal(c['journal'])
    doc=j.ensure_genesis(allow_empty=c.get('app_stream_absent_verified') is True,
        context=bound_context(c,{}))
    records=doc['records']
    # Resolve durable SENDING before any Docker/context guard can hold or return.
    record_interrupted_sends(j,records)
    records=j._read()['records']
    health=Journal(c['health_journal'])
    health.ensure_genesis(allow_empty=True,context={'deployment_id':c['deployment_id'],
        'subject_id':f"host-sender:{c['deployment_id']}:{c['run_label']}"})
    record_interrupted_sends(health,health._read()['records'])
    process_health_stream(c,health)
    current=inspect_target(c)
    ctx=bound_context(c,current)
    prior_context=next((r['context'] for r in reversed(records)
        if r.get('kind')=='TRANSITION_INTENT' and isinstance(r.get('context'),dict)),None)
    context_reconciled=any(r.get('kind')=='HELD_RECONCILIATION'
        and r.get('prior_context_digest')==sha(canonical(prior_context or {}))
        and r.get('restored_context_digest')==sha(canonical(ctx)) for r in records)
    if prior_context and prior_context!=ctx and not context_reconciled:
        j.append('HELD',{'reason':'bound-service-context-changed','prior_context':prior_context,'context':ctx}); return 3
    prior_clock=next((r for r in reversed(records) if r.get('kind') in {'SENDING','INSPECTION'} and type(r.get('clock_monotonic_ns')) is int),None)
    now_epoch=time.time(); now_mono=time.monotonic_ns(); now_boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if prior_clock and (prior_clock.get('clock_boot_id')!=now_boot or now_mono<prior_clock['clock_monotonic_ns']
            or abs(now_epoch-prior_clock['clock_epoch']-(now_mono-prior_clock['clock_monotonic_ns'])/1e9)>1):
        j.append('HELD',{'reason':'observation-clock-continuity-invalid','context':ctx}); return 3
    j.append('INSPECTION',{'clock_monotonic_ns':time.monotonic_ns(),'clock_epoch':time.time(),
        'clock_boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'state':current['state'],'context_digest':sha(canonical(ctx)),'context':ctx,'reason':current.get('reason')})
    records=j._read()['records']
    reconciled={r.get('held_sequence') for r in records if r.get('kind')=='HELD_RECONCILIATION'}
    if any(r.get('sequence') not in reconciled for r in records if r.get('kind')=='HELD'):
        return 3
    if current['state']=='unknown': return 0
    dispatch_scheduled_retries(c,j,current,ctx,records)
    records=j._read()['records']
    project_pending(c,j,records)
    edges=[r for r in records if r['kind']=='TRANSITION_INTENT']
    active_open=None
    for r in edges:
        if r['event']['transition_kind']=='opened': active_open=r
        elif r['event']['transition_kind']=='recovered': active_open=None
    if current['state']=='exited' and active_open is None:
        seq=len(edges)+1; pred=edges[-1]['event']['transition_id'] if edges else None
        # A new host genesis is admitted only for an explicitly verified absent app stream.
        if not c.get('app_stream_absent_verified',False) and not edges:
            j.append('HELD',{'reason':'app-stream-genesis-not-proven','context':ctx}); return 3
        event=edge(c,j,'opened',current,seq=seq,pred=pred,generation=sum(1 for r in edges if r['event']['transition_kind']=='opened')+1,persist=False)
        j.append('EPISODE_OPEN',{'transition_id':event['transition_id'],'context':ctx})
        state=read_json(c['observer_state']) or {}; active=read_json(c['active_file']) or {}
        identity=observer_identity(c)
        j.append('OUTAGE_BARRIER',{'transition_id':event['transition_id'],'loop_sequence':state.get('loop_sequence'),'observer_proc':identity,'boot_id':current.get('boot_id'),'target_started_at':current.get('started_at'),'timing_revision':active.get('revision'),'timing_digest':active.get('digest'),'outage_observed_epoch':time.time(),'monotonic_ns':time.monotonic_ns()})
        # Actual provider I/O occurs after the immutable intent is durable.
        send_provider(c,j,event,current)
        records=j._read()['records']; project_pending(c,j,records)
    if current['state']=='running' and active_open is not None:
        tid=active_open['event']['transition_id']
        barriers=[r for r in records if r['kind']=='OUTAGE_BARRIER' and r.get('transition_id')==tid]
        state=read_json(c['observer_state']) or {}; active=read_json(c['active_file']) or {}; identity=observer_identity(c)
        latest=barriers[-1] if barriers else None
        changed=(latest is None or latest.get('boot_id')!=current.get('boot_id')
            or latest.get('target_started_at')!=current.get('started_at')
            or latest.get('observer_proc')!=identity
            or latest.get('timing_revision')!=active.get('revision')
            or latest.get('timing_digest')!=active.get('digest'))
        if changed:
            barrier=j.append('OUTAGE_BARRIER',{'transition_id':tid,
                'loop_sequence':state.get('loop_sequence'),'observer_proc':identity,
                'boot_id':current.get('boot_id'),'target_started_at':current.get('started_at'),
                'timing_revision':active.get('revision'),'timing_digest':active.get('digest'),
                'outage_observed_epoch':time.time(),'monotonic_ns':time.monotonic_ns(),
                'rebased_from_sequence':latest.get('sequence') if latest else None})
            records=j._read()['records']
        else: barrier=latest
        recovery_context=recovery_barrier(c,barrier,j)
        if recovery_context is not None:
            previous_recovery=[r for r in records if r['kind']=='RECOVERY_BARRIER' and r.get('transition_id')==tid]
            if (not previous_recovery or previous_recovery[-1].get('source_outage_barrier_sequence')!=barrier['sequence']):
                j.append('RECOVERY_BARRIER',{'transition_id':tid,
                    'source_outage_barrier_sequence':barrier['sequence'],**recovery_context})
            elif observer_recovery(c,previous_recovery[-1],j):
                seq=len(edges)+1; pred=edges[-1]['event']['transition_id'] if edges else None; opening=active_open['event']
                recovered=edge(c,j,'recovered',current,first=opening['first_detected_at'],episode=opening['episode_id'],opening_id=opening['opening_transition_id'],seq=seq,pred=pred,generation=opening['episode_generation'],persist=False)
                send_provider(c,j,recovered,current); project_pending(c,j,j._read()['records'])
            # Missing or changed context remains unknown and cannot close the episode.
    return 0


def reconcile_held(c, operator_id, evidence_ref, *, health_only=False):
    """Explicitly release held work only when its original bound context is restored."""
    if (not isinstance(operator_id,str) or re.fullmatch(r'[A-Za-z0-9._:@-]{1,128}',operator_id) is None
            or not isinstance(evidence_ref,str)
            or re.fullmatch(r'[A-Za-z0-9._:/-]{1,256}',evidence_ref) is None):
        raise ValueError('held-reconciliation-operator-or-evidence-invalid')
    count=0
    with stream_locks(c,'sender-owner'), stream_locks(c,'authority'):
        if load_catalog(c['_path'],authority_locked=True)['_digest']!=c['_digest']:
            raise ValueError('reconciliation-catalog-changed')
        for key in (('health_journal',) if health_only else ('journal','health_journal')):
            journal=Journal(c[key]); health=key=='health_journal'
            current=health_context(c) if health else bound_context(c,inspect_target(c))
            journal.ensure_genesis(allow_empty=True if health else c.get('app_stream_absent_verified') is True,context=current)
            records=journal._read()['records']
            reconciled={r.get('held_sequence') for r in records if r.get('kind')=='HELD_RECONCILIATION'}
            held=[r for r in records if r.get('kind')=='HELD' and r['sequence'] not in reconciled]
            if not held: continue
            kinds={'SENDER_HEALTH_EDGE','HEALTH_TRANSITION_INTENT'} if health else {'TRANSITION_INTENT'}
            contexts=[r.get('context') for r in records if r.get('kind') in kinds]
            excluded={'catalog_generation','catalog_digest'}
            if not contexts or any(not isinstance(ctx,dict) or
                    {k:v for k,v in ctx.items() if k not in excluded}!=
                    {k:v for k,v in current.items() if k not in excluded} for ctx in contexts):
                raise ValueError('held-reconciliation-requires-original-context')
            for fence in held:
                for source in contexts:
                    journal.append('HELD_RECONCILIATION',{'held_sequence':fence['sequence'],
                        'operator_id':operator_id,'evidence_ref':evidence_ref,
                        'prior_context_digest':sha(canonical(source)),
                        'restored_context_digest':sha(canonical(current))})
            count+=len(held)
    return count



def run_once(c):
    """Serialize inspection, admission, edge derivation and dispatch per sender."""
    with stream_locks(c,'sender-owner'):
        rc=_run_once_locked(c)
        journal=Journal(c['journal']); doc=journal._read()
        identity=process_identity(os.getpid())
        journal.append('SENDER_LOOP_COMPLETED',{'actor':'host_sender',
            'pid':os.getpid(),'start_ticks':identity['start_ticks'],'boot_id':identity['boot_id'],
            'monotonic_ns':time.monotonic_ns(),'progress_cursor':doc['sequence'],
            'result_code':rc})
        return rc



def supervise_once(c):
    """Observe and durably report sender health; never authenticate or dispatch."""
    health=Journal(c['health_journal'])
    health.ensure_genesis(allow_empty=True,context={'deployment_id':c['deployment_id'],
        'subject_id':f"host-sender:{c['deployment_id']}:{c['run_label']}"})
    history=health._read()['records']
    sender_pid=Path(c['journal']).with_suffix('.pid')
    prior=next((r.get('state') for r in reversed(history) if r.get('kind')=='SENDER_HEALTH_EDGE'),None)
    state='healthy'; reason=None
    try:
        identity=json.loads(sender_pid.read_text())
        if (not isinstance(identity,dict) or set(identity)!={'pid','start_ticks','boot_id'}
                or type(identity['pid']) is not int or type(identity['start_ticks']) is not int
                or not isinstance(identity['boot_id'],str)):
            raise ValueError('sender-pid-identity-invalid')
        pid=identity['pid']; os.kill(pid,0)
        current=process_identity(pid)
        if current!=identity: raise ProcessLookupError()
        doc=Journal(c['journal'])._read()
        completed=next((r for r in reversed(doc['records'])
            if r.get('kind')=='SENDER_LOOP_COMPLETED'),None)
        now_mono=time.monotonic_ns()
        work_records=doc['records']+history
        known={r.get('attempt',{}).get('attempt_id') for r in work_records if r.get('kind')=='ATTEMPT_OUTCOME'}
        outstanding=[r for r in work_records if r.get('kind')=='SENDING' and r.get('attempt',{}).get('attempt_id') not in known]
        overdue=any(r.get('boot_id')!=identity['boot_id'] or type(r.get('work_deadline_monotonic_ns')) is not int
            or now_mono>r['work_deadline_monotonic_ns'] for r in outstanding)
        if overdue:
            state='unhealthy'; reason='sender_work_deadline_expired'
        elif completed is None:
            age=time.clock_gettime(time.CLOCK_BOOTTIME)-identity['start_ticks']/os.sysconf('SC_CLK_TCK')
            state='starting' if 0<=age<30 else 'unhealthy'
            reason='sender_loop_not_completed' if state=='starting' else 'sender_startup_deadline_expired'
        elif (completed.get('pid')!=pid or completed.get('start_ticks')!=identity['start_ticks']
                or completed.get('boot_id')!=identity['boot_id']
                or type(completed.get('monotonic_ns')) is not int
                or type(completed.get('progress_cursor')) is not int
                or completed['progress_cursor']>doc['sequence']
                or now_mono<completed['monotonic_ns']
                or now_mono-completed['monotonic_ns']>c['freshness_seconds']*1_000_000_000):
            state='unhealthy'; reason='sender_loop_progress_stale_or_invalid'
        else:
            known={r.get('attempt',{}).get('attempt_id') for r in doc['records']
                if r.get('kind')=='ATTEMPT_OUTCOME'}
            outstanding=[r for r in doc['records'] if r.get('kind')=='SENDING'
                and r.get('attempt',{}).get('attempt_id') not in known]
            overdue=[r for r in outstanding if r.get('boot_id')!=identity['boot_id']
                or type(r.get('work_deadline_monotonic_ns')) is not int
                or now_mono>r['work_deadline_monotonic_ns']]
            if overdue: state='unhealthy'; reason='sender_work_deadline_expired'
            else: state='healthy'; reason=None
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
        health.append('SENDER_HEALTH_EDGE',{'state':state,'failure_code':reason,
            'actor':'independent_host_supervisor','deployment_id':c['deployment_id'],
            'subject_id':f"host-sender:{c['deployment_id']}:{c['run_label']}",
            'producer_id':c['producer_id'],'binding_revision':c['binding_revision'],
            'route_revision':c['route']['revision'],'context':health_context(c)})
    else:
        health.append('SUPERVISOR_OBSERVATION',{'state':state,'failure_code':reason,'actor':'independent_host_supervisor'})
    return state


def process_identity(pid):
    stat=Path(f'/proc/{pid}/stat').read_text().split()
    return {'pid':pid,'start_ticks':int(stat[21]),
        'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}

def main():
    p=argparse.ArgumentParser(); p.add_argument('--catalog',required=True); p.add_argument('--once',action='store_true'); p.add_argument('--supervise',action='store_true'); p.add_argument('--health-only',action='store_true'); p.add_argument('--reconcile-held',action='store_true'); p.add_argument('--operator-id'); p.add_argument('--evidence-ref'); a=p.parse_args()
    c=load_catalog(a.catalog)
    if a.reconcile_held:
        if not a.operator_id or not a.evidence_ref: p.error('--reconcile-held requires --operator-id and --evidence-ref')
        print(json.dumps({'reconciled_fences':reconcile_held(c,a.operator_id,a.evidence_ref,health_only=a.health_only)},
            sort_keys=True,separators=(',',':')))
        return 0
    if a.supervise:
        while True:
            supervise_once(c)
            if a.once: return 0
            time.sleep(min(c['freshness_seconds'],10))
    if a.health_only:
        while True:
            health_only_once(c)
            if a.once: return 0
            time.sleep(min(c['freshness_seconds'],10))
    while True:
        try:
            pidfile=Path(c['journal']).with_suffix('.pid'); pidfile.parent.mkdir(mode=0o700,parents=True,exist_ok=True); atomic(pidfile,canonical(process_identity(os.getpid()))+b'\n')
            rc=run_once(c)
        except Exception as exc:
            # Avoid recursive external delivery; caller's independent supervisor owns this fault.
            try: health_only_once(c)
            except Exception: pass
            print(json.dumps({'sender':'unhealthy','failure_code':type(exc).__name__},separators=(',',':')),file=sys.stderr); return 2
        if a.once: return rc
        time.sleep(min(c['freshness_seconds'],1))
if __name__=='__main__': raise SystemExit(main())
