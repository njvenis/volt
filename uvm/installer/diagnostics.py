"""Fixed read-only diagnostics; only the actual lifecycle FD publishes results."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import sys
import time
import types
import uuid

from uvm.installer.lock import _bounded_file
from uvm.installer.offline_artifacts import canonical, digest, pairs
from uvm.installer.offline_lifecycle import owned_fd, _publish, _started_at

ROOT = Path('/state')
INPUT = Path('/run/volt-diagnostic-input')
OUTPUT = Path('/run/volt-diagnostic-output')
SETUP = Path('/package/setup.py')
MAX_BYTES, MAX_LINES, MAX_LINE, MAX_MARKERS, READ_SECONDS, SESSION_SECONDS = 65536, 1024, 2048, 256, 10, 180
REQUEST_PROFILE = 'volt_diagnostic_request_v1'
MARKERS = {
 b'G7_INIT=CE initialize': ('init_ce', None),
 b'G7_INIT=UVM migrations': ('init_uvm', None),
 b'G7_LOCAL_START=awaiting-host-acknowledgement': ('awaiting_host_ack', None),
 b'G7_LOCAL_START=host-release-validated': ('host_release_validated', None),
 b'G7_READINESS=ready': ('readiness_ready', None),
 b'G7_READINESS=recovery-control-only': ('recovery_control_only', None),
 b'G7_QUIESCE=complete': ('quiesce_complete', None),
 b'G7_STOP_DATABASE_STOPPED service=postgresql': ('stopped_postgresql', None),
 b'G7_STOP_DATABASE_STOPPED service=valkey': ('stopped_valkey', None),
 b'G7_SHUTDOWN=controlled': ('shutdown_controlled', None),
 b'G7_SHUTDOWN=failed_after_critical_exit': ('shutdown_failed_after_critical_exit', None),
 b'G7_STARTUP_INTERRUPTED phase=service-startup': ('startup_interrupted', None),
}
PHASES = ('writers', 'workers', 'databases', 'quiesce-producers', 'quiesce-admission', 'quiesce-effects', 'quiesce-consumers')
STATUS_MARKERS = [(re.compile(rb'G7_STOP_PHASE=' + phase.encode() + rb' status=([0-9]{1,3})'), 'stop_' + phase.replace('-', '_')) for phase in PHASES]
STATUS_MARKERS += [(re.compile(rb'G7_SHUTDOWN=controlled service_cleanup_status=([0-9]{1,3})'), 'shutdown_controlled'),
 (re.compile(rb'G7_CRITICAL_CHILD_EXITED status=([0-9]{1,3})'), 'critical_child_exited')]


def timestamp_ns(value):
    _started_at(value)
    base, _, fraction = value[:-1].partition('.')
    return int(datetime.fromisoformat(base).replace(tzinfo=timezone.utc).timestamp()) * 10**9 + int(fraction.ljust(9, '0') or '0')


def filter_logs(stream, started_at):
    """Bound bytes, complete lines and time; never echo an unknown log byte."""
    since = timestamp_ns(started_at); deadline = time.monotonic() + READ_SECONDS
    result = {'schema_version': 1, 'profile': 'volt_filtered_markers_v1', 'started_at': started_at,
        'markers': [], 'omitted_lines': 0, 'truncated': False, 'reader_outcome': 'complete'}
    pending = b''; count = lines = 0
    def fail(outcome):
        result['reader_outcome'] = outcome; result['truncated'] = outcome in ('byte_limit', 'line_limit', 'line_length_limit', 'marker_limit', 'partial_line', 'timeout')
        return result, 2
    def line(raw):
        nonlocal lines
        lines += 1
        if lines > MAX_LINES: return 'line_limit'
        if len(raw) > MAX_LINE: return 'line_length_limit'
        stamp, separator, message = raw.partition(b' ')
        try:
            stamp = stamp.decode('ascii')
            if not separator or timestamp_ns(stamp) < since: raise ValueError
        except (ValueError, UnicodeError):
            result['omitted_lines'] += 1; return None
        found = MARKERS.get(message)
        if found is None:
            for pattern, kind in STATUS_MARKERS:
                match = pattern.fullmatch(message)
                if match and int(match[1]) <= 255: found = (kind, int(match[1])); break
        if found is None: result['omitted_lines'] += 1
        else:
            if len(result['markers']) >= MAX_MARKERS: return 'marker_limit'
            result['markers'].append({'timestamp': stamp, 'kind': found[0], 'status': found[1]})
        return None
    try:
        descriptor = stream.fileno()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0: return fail('timeout')
            ready, _, _ = select.select([descriptor], [], [], remaining)
            if not ready: return fail('timeout')
            block = os.read(descriptor, min(4096, MAX_BYTES - count + 1))
            if not block: break
            count += len(block)
            if count > MAX_BYTES: return fail('byte_limit')
            pending += block
            while b'\n' in pending:
                raw, pending = pending.split(b'\n', 1)
                problem = line(raw)
                if problem: return fail(problem)
            if len(pending) > MAX_LINE: return fail('line_length_limit')
        if pending:
            # A partial final line cannot be authenticated as a full marker.
            result['omitted_lines'] += 1
            if result['markers']: return fail('partial_line')
            result['truncated'] = True
        if not result['markers']: return fail('no_current_markers')
        return result, 0
    except (OSError, ValueError):
        return fail('read_failed')


def private_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('diagnostic private directory differs')


def read_json(path, limit=4*1024*1024):
    return json.loads(_bounded_file(path, limit, private=True), object_pairs_hook=pairs)


def request(operation):
    if operation not in ('diagnose', 'logs'): raise ValueError('fixed diagnostic operation required')
    return {'schema_version': 1, 'profile': REQUEST_PROFILE, 'operation': operation,
        'operation_id': str(uuid.uuid4()), 'setup_sha256': digest(_bounded_file(SETUP, 1024*1024, private=False))}


def load_snapshot(setup):
    raw = _bounded_file(ROOT/'instance.json', 1024*1024, private=True)
    _, info = setup.load_instance(str(ROOT))  # Validation only, never _resume/repair.
    if info != json.loads(raw, object_pairs_hook=pairs) or _bounded_file(ROOT/'instance.json',1024*1024,private=True) != raw:
        raise ValueError('diagnostic journal changed while validated')
    if info.get('mode') != 'local': raise ValueError('fixed local diagnostic profile required')
    from uvm.installer.installed_artifacts import committed_pin
    committed_pin(info)
    from uvm.installer.recovery_authority import custody_inventory
    if custody_inventory(ROOT) != info['local_recovery_inventory']: raise ValueError('diagnostic custody changed')
    fingerprints = {'instance.json': digest(raw)}
    mutable = {'.env', 'secrets/local-restore-fence/fence.json', 'secrets/local-start-admission/admission.json'}
    for name, expected in info['installer_initial_files'].items():
        if name in mutable: continue
        if (not isinstance(name,str) or Path(name).is_absolute() or '..' in Path(name).parts or str(Path(name)) != name
                or not isinstance(expected,dict) or set(expected) != {'sha256','bytes','mode'}):
            raise ValueError('diagnostic committed host file inventory differs')
        data = _bounded_file(ROOT/name, 1024*1024, private=False)
        if (digest(data) != expected['sha256'] or len(data) != expected['bytes']
                or stat.S_IMODE((ROOT/name).lstat().st_mode) != expected['mode']):
            raise ValueError('diagnostic immutable host file changed')
        fingerprints[name] = digest(data)
    environment = _bounded_file(ROOT/'.env',1024*1024,private=True)
    if hashlib.sha256(environment).hexdigest() not in {info.get('env_sha256'), info.get('local_start_environment_pending_sha256')}:
        raise ValueError('diagnostic current/pending environment differs')
    fingerprints['.env'] = digest(environment)
    return info, fingerprints


def actual_observation(value, info):
    if not isinstance(value,dict) or set(value) != {'containers','volumes','networks','holder'}:
        raise ValueError('closed diagnostic observation required')
    project=info['project']; admitted=info['image_admission']
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,62}',project): raise ValueError('diagnostic project differs')
    holder=value['holder']
    if (not isinstance(holder,dict) or set(holder) != {'Id','Image','ImageManifestDescriptor','Config','State'}
            or not re.fullmatch(r'[0-9a-f]{64}',holder['Id'])
            or set(holder['Config']) != {'Image','Labels'} or holder['Config']['Image'] != info['image']
            or holder['Config']['Labels'].get('volt.compose.owner-token') != info['owner_token']
            or holder['Config']['Labels'].get('volt.compose.project') != project
            or set(holder['State']) != {'Running','StartedAt'} or holder['State']['Running'] is not True):
        raise ValueError('diagnostic actual FD owner differs')
    _started_at(holder['State']['StartedAt'])
    def image(item):
        if item['Image'] == admitted['id']: return
        witness=item.get('ImageManifestDescriptor') or {}; expected=admitted.get('selected_descriptor') or {}
        if (admitted.get('id_kind') != 'selected_manifest' or item['Image'] != admitted.get('engine_image_id')
                or any(witness.get(k) != expected.get(k) for k in ('digest','mediaType','size','platform'))):
            raise ValueError('diagnostic selected child witness differs')
    image(holder)
    volumes=value['volumes']; wanted={project+'_'+x for x in ('postgres','media','state')}
    if (not isinstance(volumes,list) or len(volumes)!=3 or {v.get('Name') for v in volumes} != wanted):
        raise ValueError('diagnostic owned store inventory differs')
    for volume in volumes:
        if (set(volume) != {'Name','Driver','Scope','Mountpoint','Options','Labels'} or volume['Driver']!='local'
                or volume['Scope']!='local' or volume['Options'] not in (None,{})
                or volume['Labels'].get('volt.compose.owner-token') != info['owner_token']):
            raise ValueError('diagnostic volume ownership/driver differs')
    networks=value['networks']
    if not isinstance(networks,list) or len(networks)!=1: raise ValueError('diagnostic network is missing')
    network=networks[0]
    if (set(network) != {'Name','Id','Driver','Internal','Labels','IPAM','Containers'}
            or network['Name'] != project+'_network' or network['Driver'] != 'bridge' or network['Internal'] is not False
            or not re.fullmatch(r'[0-9a-f]{64}',network['Id'])
            or network['Labels'].get('volt.compose.owner-token') != info['owner_token']
            or network['IPAM'] != {'Config':[{'Subnet':info['subnet'],'Gateway':info['gateway']}]}
            or not isinstance(network['Containers'],dict)):
        raise ValueError('diagnostic ordinary network ownership/topology differs')
    containers=value['containers']
    if not isinstance(containers,list) or len(containers)>1: raise ValueError('diagnostic API inventory differs')
    if containers:
        item=containers[0]
        if (set(item) != {'Id','Name','Image','ImageManifestDescriptor','Config','HostConfig','NetworkSettings','Mounts','State'}
                or not re.fullmatch(r'[0-9a-f]{64}',item['Id']) or item['Name'] != '/'+project+'-volt-1'
                or set(item['Config']) != {'Labels'} or set(item['HostConfig']) != {'NetworkMode'}
                or set(item['NetworkSettings']) != {'Networks'}
                or item['Config']['Labels'].get('com.docker.compose.project') != project
                or item['Config']['Labels'].get('com.docker.compose.service') != 'volt'):
            raise ValueError('diagnostic API role/identity differs')
        from uvm.installer.runtime_mounts import validate
        validate(ROOT,Path(info['host_instance_directory']),info,item,volumes)
        state=item['State']
        if (set(state) != {'Running','Status','Health','StartedAt','ExitCode','OOMKilled'}
                or any(type(state[k]) is not bool for k in ('Running','OOMKilled'))
                or state['Status'] not in ('created','running','paused','restarting','removing','exited','dead')
                or state['Health'] not in (None,'starting','healthy','unhealthy')
                or type(state['ExitCode']) is not int or not 0<=state['ExitCode']<=255):
            raise ValueError('diagnostic API state differs')
        _started_at(state['StartedAt'])
        if set(network['Containers']) - {item['Id']}: raise ValueError('diagnostic foreign network attachment')
        for endpoint in network['Containers'].values():
            if endpoint.get('Name') != project+'-volt-1': raise ValueError('diagnostic foreign endpoint')
    elif network['Containers']: raise ValueError('diagnostic unexpected network attachment')
    return value


def stable_identity(value):
    def identity(item):
        return (item['Id'],item['Image'],item['ImageManifestDescriptor'],item['Config'],item['State']['StartedAt'])
    return (identity(value['holder']), [identity(item) for item in value['containers']])


def diagnose_result(info, observed):
    item=observed['containers'][0] if observed['containers'] else None; admitted=info['image_admission']
    container={'present':False,'id':None,'running':None,'status':None,'health':None,'started_at':None,'exit_code':None,'oom_killed':None}
    if item:
        s=item['State'];container={'present':True,'id':item['Id'],'running':s['Running'],'status':s['Status'],
            'health':s['Health'],'started_at':s['StartedAt'],'exit_code':s['ExitCode'],'oom_killed':s['OOMKilled']}
    ack=info.get('local_recovery_acknowledgement'); generation=ack.get('restore_generation') if ack else None
    pending=info.get('restore_pending',False)
    if type(pending)is not bool: raise ValueError('diagnostic restore flag differs')
    phase=info.get('installer_phase')
    if phase not in ('prepared','resources-created','started','awaiting-admin','ready'): raise ValueError('diagnostic phase differs')
    if generation is not None and (type(generation) is not int or generation<0): raise ValueError('diagnostic acknowledgement differs')
    return {'schema_version':1,'profile':'volt_instance_diagnostics_v1',
      'release':{'version':admitted['version'],'source_revision':admitted['source_revision'],'source_snapshot':admitted['source_snapshot'],
        'index_digest':info['image'].split('@')[-1],'selected_digest':admitted['id'],'selected_kind':admitted['id_kind'],
        'platform':info['platform'],'bundle_sha256':info['installer_admission']['bundle_sha256']},
      'instance':{'project':info['project'],'installation_id':info['installation_id'],'phase':phase,
        'restore_pending':pending,'ack_generation':generation,'custody_ok':True},
      'container':container,'resources':{'network_name':info['project']+'_network','network_internal':False,
        'exact_attachment_set':True,'postgres_volume':info['project']+'_postgres','media_volume':info['project']+'_media',
        'state_volume':info['project']+'_state','ownership_match':True,'driver_options_empty':True},
      'private_checks':{key:True for key in ('inventory_complete','private_modes_ok','required_keys_present','fingerprints_match')}}


def identity_lines(value):
    holder=value['holder']; labels=holder['Config']['Labels']
    lines=['|'.join((holder['Id'],holder['Image'],holder['Config']['Image'],holder['State']['StartedAt'],
        'true',labels['volt.compose.owner-token'],labels['volt.compose.project']))]
    if value['containers']:
        item=value['containers'][0]; labels=item['Config']['Labels']
        lines.append('|'.join((item['Id'],item['Image'],item['State']['StartedAt'],
            labels['volt.compose.owner-token'],labels['com.docker.compose.project'])))
    else:lines.append('absent')
    return ('\n'.join(lines)+'\n').encode()


def publish_raw(name,raw):
    temporary=OUTPUT/('.diagnostic.'+uuid.uuid4().hex)
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,OUTPUT/name)
    directory=os.open(OUTPUT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)


def serve(fd):
    private_directory(INPUT); private_directory(OUTPUT)
    if any(OUTPUT.iterdir()) or {p.name for p in INPUT.iterdir()} != {'request.json'}: raise ValueError('diagnostic exchange is not new')
    request_raw=_bounded_file(INPUT/'request.json',65536,private=True); doc=json.loads(request_raw,object_pairs_hook=pairs)
    if (set(doc) != {'schema_version','profile','operation','operation_id','setup_sha256'}
            or type(doc['schema_version']) is not int or doc['schema_version']!=1 or doc['profile']!=REQUEST_PROFILE
            or doc['operation'] not in ('diagnose','logs') or str(uuid.UUID(doc['operation_id']))!=doc['operation_id']
            or canonical(doc)!=request_raw): raise ValueError('diagnostic closed request differs')
    code=_bounded_file(SETUP,1024*1024,private=False)
    if digest(code)!=doc['setup_sha256']: raise ValueError('diagnostic fixed package differs')
    setup=types.ModuleType('_volt_fixed_diagnostic_setup');setup.__file__=str(SETUP);exec(compile(code,str(SETUP),'exec'),setup.__dict__)
    deadline=time.monotonic()+SESSION_SECONDS
    def wait(name):
        while time.monotonic()<deadline:
            owned_fd(fd)
            if (INPUT/name).exists(): return read_json(INPUT/name)
            time.sleep(.05)
        raise ValueError('diagnostic exchange deadline exceeded')
    print('diagnostic_operation_id='+doc['operation_id'],flush=True)
    print('diagnostic_request_sha256='+digest(request_raw),flush=True)
    print('locked=1',flush=True)
    def observation(phase):
        value=wait(phase+'.json')
        if (not isinstance(value,dict) or set(value)!={'schema_version','profile','operation_id','request_sha256','phase','data'}
                or type(value['schema_version'])is not int or value['schema_version']!=1
                or value['profile']!='volt_diagnostic_observation_v1' or value['operation_id']!=doc['operation_id']
                or value['request_sha256']!=digest(request_raw) or value['phase']!=phase):
            raise ValueError('diagnostic stale/cross-operation observation')
        return value['data']
    before=observation('before'); receipt=read_json(INPUT/'receipt.json');info,fingerprints=load_snapshot(setup)
    from uvm.installer.installed_artifacts import validate_receipt
    validate_receipt(receipt,admitted=info['image_admission'],reference=info['image'],journal_pin=info['installer_admission'])
    actual_observation(before,info)
    after=observation('after');actual_observation(after,info)
    if stable_identity(before)!=stable_identity(after): raise ValueError('diagnostic observed identity changed')
    from uvm.installer.offline_lifecycle import canonical_resources
    normalize=lambda v:canonical_resources({'image':{},**{k:v[k] for k in ('containers','volumes','networks')}})
    # Health may legitimately progress; identity/resources must not.
    first,last=normalize(before),normalize(after)
    for value in (first,last):
        for item in value['containers']:item['State'].pop('Health')
    if first!=last: raise ValueError('diagnostic resources changed during observation')
    if load_snapshot(setup)!=(info,fingerprints) or _bounded_file(INPUT/'request.json',65536,private=True)!=request_raw:
        raise ValueError('diagnostic private journal/keys/request changed')
    validate_receipt(read_json(INPUT/'receipt.json'),admitted=info['image_admission'],reference=info['image'],journal_pin=info['installer_admission'])
    if doc['operation']=='diagnose': result=diagnose_result(info,after);exit_code=0;expected={'request.json','receipt.json','before.json','after.json'}
    else:
        parsed=read_json(INPUT/'logs.json',65536);status=read_json(INPUT/'statuses.json',4096)
        if (not after['containers'] or not isinstance(parsed,dict) or set(parsed)!= {'schema_version','profile','started_at','markers','omitted_lines','truncated','reader_outcome'}
                or parsed['profile']!='volt_filtered_markers_v1' or type(parsed['schema_version']) is not int or parsed['schema_version']!=1
                or parsed['started_at']!=after['containers'][0]['State']['StartedAt']
                or set(status)!= {'producer_exit','reader_exit'} or any(type(v)is not int or not 0<=v<=255 for v in status.values())
                or parsed['reader_outcome'] not in ('complete','byte_limit','line_limit','line_length_limit','marker_limit','partial_line','timeout','filter_unavailable','read_failed','no_current_markers')
                or type(parsed['omitted_lines'])is not int or not 0<=parsed['omitted_lines']<=1025 or type(parsed['truncated'])is not bool
                or not isinstance(parsed['markers'],list) or len(parsed['markers'])>MAX_MARKERS): raise ValueError('diagnostic bounded reader result differs')
        allowed={v[0] for v in MARKERS.values()}|{v for _,v in STATUS_MARKERS}
        for marker in parsed['markers']:
            if (not isinstance(marker,dict) or set(marker)!= {'timestamp','kind','status'} or marker['kind'] not in allowed
                    or timestamp_ns(marker['timestamp'])<timestamp_ns(parsed['started_at'])
                    or marker['status']is not None and (type(marker['status'])is not int or not 0<=marker['status']<=255)):
                raise ValueError('diagnostic marker schema differs')
        success=parsed['reader_outcome']=='complete' and bool(parsed['markers']) and not parsed['truncated']
        if (status['reader_exit']==0)!=success: raise ValueError('diagnostic reader status contradicts result')
        result={'schema_version':1,'profile':'volt_redacted_runtime_markers_v1','container_id':after['containers'][0]['Id'],
            'started_at':parsed['started_at'],'queried_tail_lines':MAX_LINES,'tail_limited':True,
            **{k:parsed[k] for k in ('markers','omitted_lines','truncated','reader_outcome')},**status}
        exit_code=int(not(success and status['producer_exit']==0));expected={'request.json','receipt.json','before.json','after.json','logs.json','statuses.json'}
    if {p.name for p in INPUT.iterdir()}!=expected: raise ValueError('diagnostic unexpected input member')
    if len(canonical(result))>65536:raise ValueError('diagnostic result exceeds serialized bound')
    owned_fd(fd);_publish(OUTPUT,'result.json',result)
    publish_raw('identity-lines',identity_lines(after))
    publish_raw('result-exit',str(exit_code).encode())
    while time.monotonic()<deadline:owned_fd(fd);time.sleep(.1)
    raise ValueError('diagnostic output owner deadline exceeded')


def main():
    parser=argparse.ArgumentParser();sub=parser.add_subparsers(dest='operation',required=True)
    emit=sub.add_parser('emit-request');emit.add_argument('action',choices=('diagnose','logs'))
    reader=sub.add_parser('filter-logs');reader.add_argument('--started-at',required=True)
    args=parser.parse_args()
    if args.operation=='emit-request':sys.stdout.buffer.write(canonical(request(args.action)));return 0
    result,code=filter_logs(sys.stdin.buffer,args.started_at);sys.stdout.buffer.write(canonical(result));return code


if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,OSError):
        print('fixed diagnostic input/reader failed',file=sys.stderr);raise SystemExit(2) from None
