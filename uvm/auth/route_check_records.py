"""Canonical STDLIB-ONLY private routing records, custody and process primitives.

Installed byte-for-byte as /usr/local/lib/volt-private/volt_route_check_records.py.
Root must load that protected file, never this API-owned package or observers.
"""
from __future__ import annotations

import base64
import ctypes
import errno
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
import uuid
from urllib.parse import urlsplit

PROFILE = 'volt_transient_route_check_v1'
LAUNCH_PROFILE = 'volt_main_api_launch_v1'
LAUNCH_RECORD_PROFILE = 'volt_main_api_launch_v2'
MAIN_API_RECIPE = 'uvm_main_api_v2'
READINESS_PROFILES = frozenset(prefix+'_'+mode for prefix in ('normal','verification')
    for mode in ('local_https','local_loopback','oidc','bearer'))
OBSERVED_READINESS_PROFILE = 'normal_local_https'
LOCAL_BACKUP_PROFILES = frozenset({'normal_local_https','normal_local_loopback'})
LOCAL_CONFIG_SOURCE = Path('/run/secrets/local-auth.json')
LOCAL_CONFIG_STAGE = Path('/etc/volt/local-auth.json')
DIRECTORY = Path('/run/uvm-route-check')
READY_DIRECTORY = Path('/run/uvm-g7')
LIMIT = 8192
TTL_NS = 60_000_000_000
ERRORS = frozenset({'invalid_input','custody_invalid','process_not_ready','identity_mismatch',
    'operation_conflict','operation_expired','observation_missing','state_inconsistent','cleanup_failed'})
PHASES = {'starting','ready','stopping','stopped','failed'}
DIRTY_RESULTS = frozenset({'forced_stop','api_nonzero','cleanup_failed'})
TERMINAL_PROFILE = 'volt_main_api_terminal_v1'
COMPLETION_REQUEST_PROFILE = 'volt_main_api_completion_request_v1'
COMPLETION_PROFILE = 'volt_main_api_completion_v1'
STOP_PROGRESS_PROFILE = 'volt_main_api_stop_progress_v1'
SESSION_FAILURES = DIRTY_RESULTS | {'unexpected_api_exit','publication_failed','terminal_channel_failed'}
_BROKER_SESSIONS = {}
_SESSION_TOKEN = object()
REASONS = {'completed','cancelled','expired','startup','shutdown','api_dead'}
BASE = {'schema_version','profile'}
ROOT_TEMPS = re.compile(r'\.tmp-(supervisor|state|launch|launch-status)-[0-9a-f]{32}\Z')
API_TEMPS = re.compile(r'\.tmp-(boot|seen)-[0-9a-f]{32}\Z')


class RouteCheckError(RuntimeError):
    def __init__(self, code):
        self.code = code if code in ERRORS else 'state_inconsistent'
        super().__init__(self.code)


def fail(code):
    raise RouteCheckError(code)


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')


def _pairs(items):
    result = {}
    for key,value in items:
        if key in result: fail('invalid_input')
        result[key] = value
    return result


def _obj(value, fields):
    if type(value) is not dict or set(value) != set(fields): fail('invalid_input')


def _int(value, low=0, high=(1 << 63)-1):
    if type(value) is not int or not low <= value <= high: fail('invalid_input')


def _text(value, pattern):
    if type(value) is not str or re.fullmatch(pattern,value) is None: fail('invalid_input')


def _uuid(value, operation=False):
    try:
        parsed = uuid.UUID(value)
        if type(value) is not str or str(parsed) != value or operation and parsed.version != 4: raise ValueError
    except (ValueError,TypeError,AttributeError): fail('invalid_input')


def _nonce(value):
    _text(value,r'[A-Za-z0-9_-]{43}')
    if base64.urlsafe_b64encode(base64.urlsafe_b64decode(value+'=')).decode().rstrip('=') != value:
        fail('invalid_input')


def new_nonce():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')


def _origin(value):
    if type(value) is not str: fail('invalid_input')
    try:
        u=urlsplit(value)
        if (u.scheme!='https' or not u.hostname or u.username is not None or u.password is not None
                or u.path or u.query or u.fragment or not u.netloc or not value.isascii()
                or u.hostname != u.hostname.lower() or u.hostname.endswith('.')
                or u.port is not None and not 1<=u.port<=65535): raise ValueError
        host=('['+u.hostname+']') if ':' in u.hostname else u.hostname
        expected='https://'+host+((':'+str(u.port)) if u.port is not None else '')
        if value!=expected: raise ValueError
    except ValueError: fail('invalid_input')


def _process(value):
    _obj(value,{'pid','proc_start_ticks'});_int(value['pid'],1,2147483647);_int(value['proc_start_ticks'],1)


def _image(value):
    _obj(value,{'kind','id','config_id'})
    if value['kind'] not in {'config','selected_manifest'}: fail('invalid_input')
    for k in ('id','config_id'): _text(value[k],r'sha256:[0-9a-f]{64}')
    if value['kind']=='config' and value['id']!=value['config_id']: fail('invalid_input')


def _runtime(value):
    _obj(value,{'container_id','started_at','image','resources_sha256'})
    _text(value['container_id'],r'[0-9a-f]{64}');_text(value['resources_sha256'],r'[0-9a-f]{64}')
    _text(value['started_at'],r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z')
    from datetime import datetime
    try: datetime.fromisoformat(value['started_at'].replace('Z','+00:00'))
    except ValueError: fail('invalid_input')
    _image(value['image'])


ARM_FIELDS = BASE | {'operation_id','installation_id','journal_id','restore_generation','recovery_epoch_id',
    'container_id','started_at','image','resources_sha256','public_origin','runtime_boot_nonce','api','challenge',
    'issued_utc_ns','expires_utc_ns','issued_boottime_ns','expires_boottime_ns'}
INTENT_FIELDS = ARM_FIELDS-BASE-{'issued_utc_ns','expires_utc_ns','issued_boottime_ns','expires_boottime_ns'}|{'ttl_ns'}


def _arm_common(value):
    _uuid(value['operation_id'],True)
    for k in ('installation_id','journal_id'): _uuid(value[k])
    _int(value['restore_generation'])
    if value['restore_generation']==0:
        if value['recovery_epoch_id'] is not None: fail('invalid_input')
    else: _uuid(value['recovery_epoch_id'])
    _runtime({k:value[k] for k in ('container_id','started_at','image','resources_sha256')})
    _origin(value['public_origin']);_nonce(value['runtime_boot_nonce']);_nonce(value['challenge']);_process(value['api'])


def _validate(kind,v):
    private_profiles={'terminal':TERMINAL_PROFILE,'completion_request':COMPLETION_REQUEST_PROFILE,
        'completion':COMPLETION_PROFILE,'api_stop_progress':STOP_PROGRESS_PROFILE}
    if kind in private_profiles:
        _obj_base(v,private_profiles[kind])
        fields=BASE|{'entrypoint','supervisor','api'}
        for key in ('entrypoint','supervisor','api'):_process(v[key])
        if len({v[key]['pid'] for key in ('entrypoint','supervisor','api')})!=3:fail('invalid_input')
        if kind!='api_stop_progress':
            fields|={'operation_id'};_text(v['operation_id'],r'[0-9a-f]{64}')
        if kind=='terminal':
            fields|={'result','reason'}
            if (v['result'],v['reason']) not in {('success','none'),('failure','service_cleanup_failed'),('failure','lifecycle_failed')}:fail('invalid_input')
        if kind in {'completion','api_stop_progress'}:
            fields|={'launch_sha256','status_sha256'}
            for k in ('launch_sha256','status_sha256'):_text(v[k],r'[0-9a-f]{64}')
        if kind=='completion':
            fields|={'broker_wait_exit_code'}
            if type(v['broker_wait_exit_code']) is not int or v['broker_wait_exit_code']!=0:fail('invalid_input')
        _obj(v,fields);return
    if kind in {'launch','launch_status'}:
        _obj_base(v,LAUNCH_RECORD_PROFILE if kind=='launch' else LAUNCH_PROFILE)
        common=BASE|{'entrypoint','supervisor','api'}
        for key in ('entrypoint','supervisor','api'):_process(v[key])
        if len({v[key]['pid'] for key in ('entrypoint','supervisor','api')})!=3:fail('invalid_input')
        if kind=='launch':
            _obj(v,common|{'recipe','clock_ticks_per_second','executable','exec_utc_ns','exec_boottime_ns','readiness_profile'})
            if v['readiness_profile'] not in READINESS_PROFILES:fail('invalid_input')
            if v['recipe']!=MAIN_API_RECIPE:fail('invalid_input')
            _int(v['clock_ticks_per_second'],1,2147483647)
            e=v['executable'];_obj(e,{'device','inode','mode','uid','gid','size'})
            _int(e['device'],0,2**64-1);_int(e['inode'],1,2**64-1);_int(e['gid'],0,2**32-1);_int(e['size'],1,67108864)
            if type(e['mode']) is not int or e['mode']!=0o755 or type(e['uid']) is not int or e['uid']!=0:fail('invalid_input')
            _int(v['exec_utc_ns']);_int(v['exec_boottime_ns'])
        else:
            _obj(v,common|{'phase','result','updated_utc_ns','updated_boottime_ns'})
            allowed={'running':{'none'},'quiescing':{'none'},'stopping':{'none'},
                'quiesce_failed':{'quiesce_timeout'},'api_stopped':{'none','api_nonzero','forced_stop','cleanup_failed'},'failed':{'api_nonzero','forced_stop','cleanup_failed'},
                'stopped':{'clean_stop','forced_stop','cleanup_failed'}}
            if type(v['phase']) is not str or v['phase'] not in allowed or v['result'] not in allowed[v['phase']]:fail('invalid_input')
            _int(v['updated_utc_ns']);_int(v['updated_boottime_ns'])
        return
    if kind=='start_admission':
        _validate_start_admission(v);return
    if kind=='intent':
        _obj(v,INTENT_FIELDS);_arm_common(v);_int(v['ttl_ns'],1,TTL_NS);return
    if kind=='request':
        _obj_base(v)
        fields=set(v)-BASE
        if not fields: return
        if fields=={'intent'}: _validate('intent',v['intent']);return
        if fields=={'arm'}: _validate('arm',v['arm']);return
        if fields=={'api'}: _process(v['api']);return
        if fields=={'operation_id','runtime_boot_nonce','api'}:
            _uuid(v['operation_id'],True);_nonce(v['runtime_boot_nonce']);_process(v['api']);return
        fail('invalid_input')
    _obj_base(v)
    if kind=='arm':
        _obj(v,ARM_FIELDS);_arm_common(v)
        for key in ('issued_utc_ns','expires_utc_ns','issued_boottime_ns','expires_boottime_ns'): _int(v[key])
        duration=v['expires_utc_ns']-v['issued_utc_ns']
        if not 0<duration<=TTL_NS or duration!=v['expires_boottime_ns']-v['issued_boottime_ns']: fail('invalid_input')
    elif kind=='supervisor':
        _obj(v,BASE|{'supervisor','api','clock_ticks_per_second','phase'})
        _process(v['supervisor']);_process(v['api']);_int(v['clock_ticks_per_second'],1)
        if v['phase'] not in PHASES: fail('invalid_input')
    elif kind=='boot':
        _obj(v,BASE|{'runtime_boot_nonce','api','published_boottime_ns','ready','loaded_operation_id'})
        _nonce(v['runtime_boot_nonce']);_process(v['api']);_int(v['published_boottime_ns'])
        if type(v['ready']) is not bool: fail('invalid_input')
        if v['loaded_operation_id'] is not None: _uuid(v['loaded_operation_id'],True)
    elif kind=='seen':
        _obj(v,BASE|{'operation_id','runtime_boot_nonce','api','challenge_sha256','observed_utc_ns','observed_boottime_ns'})
        _uuid(v['operation_id'],True);_nonce(v['runtime_boot_nonce']);_process(v['api'])
        _text(v['challenge_sha256'],r'[0-9a-f]{64}')
        for key in ('observed_utc_ns','observed_boottime_ns'): _int(v[key])
    elif kind=='disarmed':
        _obj(v,BASE|{'runtime_boot_nonce','api','runtime','reason','operation_id'})
        if v['reason'] not in REASONS: fail('invalid_input')
        if v['runtime_boot_nonce'] is not None: _nonce(v['runtime_boot_nonce'])
        if v['api'] is not None: _process(v['api'])
        if v['runtime'] is not None: _runtime(v['runtime'])
        if v['operation_id'] is not None: _uuid(v['operation_id'],True)
        if v['reason']!='startup' and (v['runtime_boot_nonce'] is None or v['api'] is None): fail('invalid_input')
    elif kind=='state':
        _obj(v,BASE|{'state','arm','disarmed','closing_reason'})
        if v['state']=='disarmed':
            if v['arm'] is not None or v['closing_reason'] is not None: fail('invalid_input')
            _validate('disarmed',v['disarmed'])
        elif v['state'] in {'armed','closing'}:
            _validate('arm',v['arm'])
            if v['disarmed'] is not None: fail('invalid_input')
            if v['state']=='armed' and v['closing_reason'] is not None: fail('invalid_input')
            if v['state']=='closing' and v['closing_reason'] not in REASONS-{'startup'}: fail('invalid_input')
        else: fail('invalid_input')
    else: fail('invalid_input')


def _obj_base(v,profile=PROFILE):
    if type(v) is not dict or not BASE<=set(v) or type(v['schema_version']) is not int or v['schema_version']!=1 or v['profile']!=profile:
        fail('invalid_input')


def validate_record(kind, raw: bytes) -> dict:
    """Closed wire parser. Request dispatch is by exact field set, not input opcode."""
    if type(raw) is not bytes or not raw or len(raw)>LIMIT: fail('invalid_input')
    try:
        value=json.loads(raw,object_pairs_hook=_pairs,parse_constant=lambda _:fail('invalid_input'))
        _validate(kind,value)
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError): fail('invalid_input')
    return value


def record(**values):
    return {'schema_version':1,'profile':PROFILE,**values}


def boottime_ns():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def check_fresh(arm, *, utc_ns=None, mono_ns=None):
    utc=time.time_ns() if utc_ns is None else utc_ns;mono=boottime_ns() if mono_ns is None else mono_ns
    if not (arm['issued_boottime_ns']<=mono<=arm['expires_boottime_ns']
            and arm['issued_utc_ns']-2_000_000_000<=utc<=arm['expires_utc_ns']): fail('operation_expired')


def proc_metadata(pid):
    """Private process metadata for fixed supervisor/API identities, never HTTP."""
    _int(pid,1,2147483647)
    try:
        path=Path('/proc')/str(pid)
        before=(path/'stat').read_bytes();tail=before[before.rindex(b')')+2:].split()
        status=(path/'status').read_text();ids={line.split(':',1)[0]:line.split(':',1)[1].split()
            for line in status.splitlines() if ':' in line}
        # Linux restricts cross-UID /proc/exe; API needs stat/status liveness,
        # while the root publisher additionally checks exact executable/argv.
        try:exe=os.readlink(path/'exe')
        except PermissionError:exe=None
        try:argv=tuple(x.decode('utf-8') for x in (path/'cmdline').read_bytes().split(b'\0') if x)
        except PermissionError:argv=None
        value={'identity':{'pid':pid,'proc_start_ticks':int(tail[19])},'state':tail[0].decode('ascii'),
            'ppid':int(tail[1]),'pgrp':int(tail[2]),'session':int(tail[3]),
            'uids':tuple(map(int,ids['Uid'])),'gids':tuple(map(int,ids['Gid'])),
            'exe':exe,'argv':argv}
        after=(path/'stat').read_bytes();aft=after[after.rindex(b')')+2:].split()
        if tail[19]!=aft[19] or tail[1:4]!=aft[1:4] or aft[0] not in {b'R',b'S',b'D'}: fail('process_not_ready')
        _process(value['identity']);return value
    except (OSError,ValueError,KeyError,IndexError,UnicodeError): fail('process_not_ready')


def validated_proc_identity(pid:int)->dict:
    return proc_metadata(pid)['identity']


def proc_live(identity):
    try: return validated_proc_identity(identity['pid'])==identity
    except RouteCheckError: return False


def proc_dead(identity):
    """Prove the ORIGINAL identity cannot run; stopped/uncertain is never dead."""
    _process(identity)
    path=Path('/proc')/str(identity['pid'])/'stat'
    try:
        first=path.read_bytes();a=first[first.rindex(b')')+2:].split()
        second=path.read_bytes();b=second[second.rindex(b')')+2:].split()
        start_a=int(a[19]);start_b=int(b[19])
        if start_a!=start_b:fail('process_not_ready')
        if start_a!=identity['proc_start_ticks']:return True
        if a[0] in {b'Z',b'X',b'x'} and b[0] in {b'Z',b'X',b'x'}:return True
        if b[0] in {b'R',b'S',b'D',b'T',b't',b'I'}:return False
        fail('process_not_ready')
    except FileNotFoundError:return True
    except ProcessLookupError:return True
    except (OSError,ValueError,IndexError):fail('process_not_ready')


def validate_launch_processes(launch,*,own_api=False):
    validate_record('launch',canonical(launch))
    if launch['clock_ticks_per_second']!=os.sysconf('SC_CLK_TCK'):fail('process_not_ready')
    entry=proc_metadata(launch['entrypoint']['pid']);broker=proc_metadata(launch['supervisor']['pid']);api=proc_metadata(launch['api']['pid'])
    for key,info in (('entrypoint',entry),('supervisor',broker),('api',api)):
        expected=1800 if key=='api' else 0
        if info['identity']!=launch[key] or info['uids']!=(expected,)*4 or info['gids']!=(expected,)*4:fail('process_not_ready')
    if (broker['ppid']!=entry['identity']['pid'] or api['ppid']!=broker['identity']['pid']
            or api['session']!=api['identity']['pid'] or api['pgrp']!=api['identity']['pid']
            or own_api and api['identity']['pid']!=os.getpid()
            or launch['exec_boottime_ns']>boottime_ns() or launch['exec_utc_ns']>time.time_ns()+2_000_000_000):fail('process_not_ready')
    return launch['api']


def _open_readiness_directory():
    # Fixed root-only parent condition. No API read or unsafe-directory adoption.
    if os.geteuid()!=0:fail('custody_invalid')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        parts=READY_DIRECTORY.parts[1:]
        for index,part in enumerate(parts):
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            try:
                info=os.fstat(child)
                if (info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)&0o022
                        or index==len(parts)-1 and stat.S_IMODE(info.st_mode)!=0o700):fail('custody_invalid')
            except BaseException:os.close(child);raise
            os.close(fd);fd=child
        return fd
    except BaseException:os.close(fd);raise


def parent_ready_condition(*,require_absent=False):
    """Fixed root-only read; absence is ordinary pending, unsafe custody denies."""
    directory=_open_readiness_directory()
    try:
        for name in ('critical-failed','quiesce-failed'):
            try:os.stat(name,dir_fd=directory,follow_symlinks=False)
            except FileNotFoundError:pass
            else:fail('process_not_ready')
        try:fd=os.open('ready',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        except FileNotFoundError:return False
        try:
            before=os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_gid!=0
                    or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1
                    or before.st_size!=0 or os.read(fd,1)):fail('custody_invalid')
            if _identity(before)!=_identity(os.fstat(fd)) or _identity(before)!=_identity(os.stat('ready',dir_fd=directory,follow_symlinks=False)):fail('custody_invalid')
            if require_absent:fail('operation_conflict')
            return True
        finally:os.close(fd)
    except OSError:fail('custody_invalid')
    finally:os.close(directory)


def _original_broker(launch):
    if os.geteuid()!=0 or launch['supervisor']['pid']!=os.getpid():fail('identity_mismatch')
    own=proc_metadata(os.getpid());parent=proc_metadata(launch['entrypoint']['pid'])
    if (own['identity']!=launch['supervisor'] or parent['identity']!=launch['entrypoint']
            or own['ppid']!=parent['identity']['pid'] or own['uids']!=(0,)*4 or own['gids']!=(0,)*4
            or parent['uids']!=(0,)*4 or parent['gids']!=(0,)*4):fail('identity_mismatch')


def _launch_key(launch):return hashlib.sha256(canonical(launch)).hexdigest()


def _strict_private(kind,raw,*,launch):
    if type(raw) is not bytes or not 1<=len(raw)<=2048:fail('invalid_input')
    value=validate_record(kind,raw)
    if canonical(value)!=raw:fail('invalid_input')
    if any(value[k]!=launch[k] for k in ('entrypoint','supervisor','api')):fail('identity_mismatch')
    return value


def encode_terminal_frame(value):
    raw=canonical(value);validate_record('terminal',raw)
    if len(raw)>2048:fail('invalid_input')
    return len(raw).to_bytes(4,'big')+raw


def decode_terminal_frame(raw,*,launch):
    if type(raw) is not bytes or not 5<=len(raw)<=2052 or int.from_bytes(raw[:4],'big')!=len(raw)-4:fail('invalid_input')
    return _strict_private('terminal',raw[4:],launch=launch)


def validate_completion_request(raw,*,launch):
    return _strict_private('completion_request',raw,launch=launch)


def validate_completion_envelope(raw,*,launch,status):
    # Validates a CANDIDATE envelope only; caller must additionally join actual
    # original-broker/PID1 kernel completion and current host-controlled stop.
    value=_strict_private('completion',raw,launch=launch)
    validate_record('launch_status',canonical(status))
    if (status['phase']!='stopped' or status['result']!='clean_stop'
            or any(status[k]!=launch[k] for k in ('entrypoint','supervisor','api'))
            or value['launch_sha256']!=_launch_key(launch)
            or value['status_sha256']!=hashlib.sha256(canonical(status)).hexdigest()):fail('identity_mismatch')
    return value


def _read_launch_unlocked():
    # Immutable root publication; no nested flock while caller holds Store lock.
    parent=_open_parent()
    try:return _Store('api',parent,None)._read('launch.json','launch')
    finally:os.close(parent)


def validate_supervision(value,*,require_ready=True,own_api=False,launch=None):
    launch=_read_launch_unlocked() if launch is None else launch
    if launch['readiness_profile']!=OBSERVED_READINESS_PROFILE:fail('process_not_ready')
    validate_launch_processes(launch,own_api=own_api)
    if (value['supervisor']!=launch['supervisor'] or value['api']!=launch['api']
            or value['clock_ticks_per_second']!=launch['clock_ticks_per_second']
            or value['phase'] not in ({'ready'} if require_ready else {'starting','ready'})):fail('process_not_ready')
    if require_ready:
        parent=_open_parent()
        try:status=_Store('api',parent,None)._read('launch-status.json','launch_status',optional=True)
        finally:os.close(parent)
        if (not status or status['phase']!='running' or status['result']!='none'
                or any(status[k]!=launch[k] for k in ('entrypoint','supervisor','api'))):fail('process_not_ready')
    return value['api']


def _identity(info):
    return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def _directory(fd,uid,gid,mode):
    info=os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(uid,gid,mode): fail('custody_invalid')


def _regular(info,uid,mode,*,lock=False):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=uid or info.st_gid!=1800 or stat.S_IMODE(info.st_mode)!=mode
            or info.st_nlink!=1 or info.st_size>(0 if lock else LIMIT)): fail('custody_invalid')


def _open_parent():
    fd=os.open('/',os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for part in DIRECTORY.parts[1:]:
            child=os.open(part,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);os.close(fd);fd=child
        _directory(fd,0,1800,0o710);return fd
    except BaseException:
        os.close(fd);raise


def _rename_no_replace(source_dir,source,target_dir,target):
    """Linux atomic no-replace; deliberately no hard-link or replace fallback."""
    libc=ctypes.CDLL(None,use_errno=True)
    try:rename=libc.renameat2
    except AttributeError:fail('cleanup_failed')
    rename.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
    rename.restype=ctypes.c_int
    if rename(source_dir,source.encode('ascii'),target_dir,target.encode('ascii'),1)!=0:
        error=ctypes.get_errno()
        if error==errno.EEXIST:fail('operation_conflict')
        fail('cleanup_failed')


def _broker_publication(method):
    def guarded(self,value):
        try:
            launch=value if method.__name__=='publish_launch' else self.read_launch()
            _original_broker(launch)
        except BaseException:
            for known in _BROKER_SESSIONS.values():
                if known._launch['supervisor']['pid']==os.getpid():known.note_failure('publication_failed')
            raise
        session=_BROKER_SESSIONS.get(_launch_key(launch))
        try:
            if session is not None:session._check()
            if method.__name__=='publish_launch_status':
                if session is None:fail('state_inconsistent')
                if value.get('result') in DIRTY_RESULTS:session.note_failure(value['result'])
                if value.get('result')=='clean_stop' and not session._finishing:fail('operation_conflict')
                if value.get('phase')=='api_stopped' and not session._publishing_progress:fail('operation_conflict')
                if session.failure is not None and value.get('result') not in DIRTY_RESULTS:fail('operation_conflict')
            if method.__name__=='publish_supervisor':
                if session is None:fail('state_inconsistent')
                if session.failure is not None and value.get('phase') in {'starting','ready'}:fail('operation_conflict')
                if value.get('phase')=='ready' and not session._acknowledging_ready:fail('operation_conflict')
            return method(self,value)
        except BaseException:
            if session is not None:session.note_failure('publication_failed')
            raise
    return guarded


class _Store:
    """Fixed record methods only. Instances exist only while the shared lock is held."""
    def __init__(self,role,parent,api): self.role=role;self._parent=parent;self._api=api;self._valid=True
    def _assert(self,root=False):
        if not self._valid or root and self.role!='root': fail('custody_invalid')
    def _read_raw(self,name,kind,*,api=False,optional=False):
        self._assert();directory=self._api if api else self._parent;uid=1800 if api else 0;mode=0o600 if api else 0o640
        try: fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        except FileNotFoundError:
            if optional:return None
            fail('state_inconsistent')
        try:
            before=os.fstat(fd);_regular(before,uid,mode);raw=os.read(fd,LIMIT+1)
            if len(raw)!=before.st_size or _identity(before)!=_identity(os.fstat(fd)) or _identity(before)!=_identity(os.stat(name,dir_fd=directory,follow_symlinks=False)): fail('custody_invalid')
            validate_record(kind,raw);return raw
        finally:os.close(fd)
    def _read(self,name,kind,*,api=False,optional=False):
        raw=self._read_raw(name,kind,api=api,optional=optional)
        return None if raw is None else validate_record(kind,raw)
    def read_supervisor(self):return self._read('supervisor.json','supervisor')
    def read_state(self):return self._read('state.json','state')
    def read_launch(self):return self._read('launch.json','launch')
    def read_launch_status(self):return self._read('launch-status.json','launch_status',optional=True)
    def _read_profile_health(self,*,verification):
        self._assert(root=True)
        if not parent_ready_condition():return False
        launch=self.read_launch();sup=self.read_supervisor()
        if launch['readiness_profile'].startswith('verification_')!=verification:return False
        try:
            validate_launch_processes(launch)
            if (sup['phase']!='ready' or sup['supervisor']!=launch['supervisor'] or sup['api']!=launch['api']
                    or sup['clock_ticks_per_second']!=launch['clock_ticks_per_second']):return False
            status=self.read_launch_status()
            if (status is None or status['phase']!='running' or status['result']!='none'
                    or any(status[k]!=launch[k] for k in ('entrypoint','supervisor','api'))):return False
            self._require_profile_observations(launch)
        except RouteCheckError:return False
        return True
    def read_broker_ready(self):return self._read_profile_health(verification=False)
    def read_verification_health(self):return self._read_profile_health(verification=True)
    def _require_profile_observations(self,launch):
        boot=self.read_boot()
        if launch['readiness_profile']==OBSERVED_READINESS_PROFILE:
            if (not boot or not boot['ready'] or boot['api']!=launch['api']
                    or boot['published_boottime_ns']<launch['exec_boottime_ns']):fail('process_not_ready')
        elif boot is not None or self.read_seen() is not None or self.read_state()['state']!='disarmed':
            fail('state_inconsistent')
    def read_completion_candidate(self,request_raw):
        """Read-only CANDIDATE, never proof of original wait0 or host completion."""
        self._assert(root=True)
        launch_raw=self._read_raw('launch.json','launch');launch=validate_record('launch',launch_raw)
        request=validate_completion_request(request_raw,launch=launch)
        status_raw=self._read_raw('launch-status.json','launch_status');status=validate_record('launch_status',status_raw)
        if launch_raw!=canonical(launch) or status_raw!=canonical(status):fail('invalid_input')
        if (status['phase']!='stopped' or status['result']!='clean_stop'
                or any(status[k]!=launch[k] for k in ('entrypoint','supervisor','api'))):fail('state_inconsistent')
        supervisor=self.read_supervisor()
        if (supervisor['phase']!='stopped' or supervisor['supervisor']!=launch['supervisor']
                or supervisor['api']!=launch['api'] or supervisor['clock_ticks_per_second']!=launch['clock_ticks_per_second']):fail('identity_mismatch')
        if not proc_dead(launch['supervisor']):fail('process_not_ready')
        self._require_stopped_api(launch)
        if self.read_boot() is not None:fail('state_inconsistent')
        envelope={'schema_version':1,'profile':COMPLETION_PROFILE,
            **{k:launch[k] for k in ('entrypoint','supervisor','api')},'operation_id':request['operation_id'],
            'launch_sha256':hashlib.sha256(launch_raw).hexdigest(),
            'status_sha256':hashlib.sha256(status_raw).hexdigest(),'broker_wait_exit_code':0}
        # This literal describes the envelope shape, NOT an observation of
        # waitpid. Only original PID1's causal wait0 may authorize its producer.
        envelope_raw=canonical(envelope);validate_completion_envelope(envelope_raw,launch=launch,status=status)
        return {'launch':launch,'status':status,'launch_raw':launch_raw,'status_raw':status_raw,
            'envelope':envelope,'envelope_raw':envelope_raw}
    def read_api_stop_progress(self):
        self._assert(root=True);launch=self.read_launch();status=self.read_launch_status()
        if status is None or status['phase']!='api_stopped':return None
        if any(status[k]!=launch[k] for k in ('entrypoint','supervisor','api')):fail('identity_mismatch')
        broker=proc_metadata(launch['supervisor']['pid']);entry=proc_metadata(launch['entrypoint']['pid'])
        if (broker['identity']!=launch['supervisor'] or entry['identity']!=launch['entrypoint']
                or broker['ppid']!=entry['identity']['pid'] or broker['uids']!=(0,)*4 or broker['gids']!=(0,)*4
                or entry['uids']!=(0,)*4 or entry['gids']!=(0,)*4):fail('process_not_ready')
        sup=self.read_supervisor()
        if (sup['supervisor']!=launch['supervisor'] or sup['api']!=launch['api']
                or sup['phase'] not in {'stopping','failed'}):fail('state_inconsistent')
        self._require_stopped_api(launch)
        if self.read_boot() is not None:fail('state_inconsistent')
        return {'schema_version':1,'profile':STOP_PROGRESS_PROFILE,
            **{k:launch[k] for k in ('entrypoint','supervisor','api')},
            'launch_sha256':_launch_key(launch),'status_sha256':hashlib.sha256(canonical(status)).hexdigest()}
    def read_boot(self):return self._read('boot.json','boot',api=True,optional=True)
    def read_seen(self):return self._read('seen.json','seen',api=True,optional=True)
    def _publish(self,name,kind,value,*,api=False,exclusive=False):
        self._assert(root=not api)
        if api and self.role!='api':fail('custody_invalid')
        raw=canonical(value);validate_record(kind,raw)
        directory=self._api if api else self._parent;uid=1800 if api else 0;mode=0o600 if api else 0o640
        temp='.tmp-'+('launch-status' if kind=='launch_status' else kind)+'-'+secrets.token_hex(16);fd=None
        try:
            fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode,dir_fd=directory)
            if self.role=='root':os.fchown(fd,uid,1800)
            os.fchmod(fd,mode);_regular(os.fstat(fd),uid,mode)
            offset=0
            while offset<len(raw):offset+=os.write(fd,raw[offset:])
            os.fsync(fd);os.close(fd);fd=None
            if exclusive:
                _rename_no_replace(directory,temp,directory,name)
            else:os.replace(temp,name,src_dir_fd=directory,dst_dir_fd=directory)
            _sync(directory)
        except OSError:fail('cleanup_failed')
        finally:
            if fd is not None:os.close(fd)
            try:os.unlink(temp,dir_fd=directory)
            except FileNotFoundError:pass
    @_broker_publication
    def publish_launch(self,value):
        self._assert(root=True);validate_record('launch',canonical(value))
        if value['supervisor']['pid']!=os.getpid():fail('identity_mismatch')
        validate_launch_processes(value)
        current=self._read('launch.json','launch',optional=True)
        if current!=value:parent_ready_condition(require_absent=True)
        if current is not None and current!=value:
            if not proc_dead(current['api']) or not proc_dead(current['supervisor']):fail('operation_conflict')
            if self.read_state()['state']!='disarmed' or self.read_boot() is not None or self.read_seen() is not None or self.inventory():fail('state_inconsistent')
            # Only retirement of a proved-dead launch may discard its outcome.
            # Do not adopt/delete another valid namespace's durable records.
            try:old_supervisor=self._read('supervisor.json','supervisor',optional=True)
            except RouteCheckError as exc:
                if exc.code!='invalid_input':raise
                old_supervisor=None
            if old_supervisor is not None and (old_supervisor['api']!=current['api'] or old_supervisor['supervisor']!=current['supervisor']):fail('identity_mismatch')
            try:old_status=self.read_launch_status()
            except RouteCheckError as exc:
                if exc.code!='invalid_input':raise
                old_status=None
            if old_status is not None and any(old_status[k]!=current[k] for k in ('entrypoint','supervisor','api')):fail('identity_mismatch')
            for name in ('launch-status.json','supervisor.json'):
                try:os.unlink(name,dir_fd=self._parent)
                except FileNotFoundError:pass
            _sync(self._parent)
        self._publish('launch.json','launch',value)
    @_broker_publication
    def publish_launch_status(self,value):
        self._assert(root=True);validate_record('launch_status',canonical(value))
        launch=self.read_launch()
        if any(value[k]!=launch[k] for k in ('entrypoint','supervisor','api')):fail('identity_mismatch')
        previous=self.read_launch_status()
        same=previous is not None and all(previous[k]==value[k] for k in ('entrypoint','supervisor','api'))
        if same and (value['updated_boottime_ns']<previous['updated_boottime_ns']
                or value['updated_utc_ns']<previous['updated_utc_ns']):fail('state_inconsistent')
        supervisor=self.read_supervisor()
        if supervisor['supervisor']!=launch['supervisor'] or supervisor['api']!=launch['api']:fail('identity_mismatch')
        transitions={'running':{'running','quiescing','quiesce_failed','stopping','api_stopped','stopped','failed'},
            'quiescing':{'quiescing','quiesce_failed','stopping','api_stopped','stopped','failed'},
            'quiesce_failed':{'quiesce_failed','stopping','api_stopped','stopped','failed'},
            'stopping':{'stopping','api_stopped','stopped','failed'},'api_stopped':{'api_stopped','stopped','failed'},'failed':{'failed','stopping','api_stopped','stopped'},'stopped':{'stopped'}}
        if same and value['phase'] not in transitions[previous['phase']]:fail('operation_conflict')
        dirty=same and previous['result'] in DIRTY_RESULTS
        if dirty and value['result'] not in DIRTY_RESULTS:fail('operation_conflict')
        # A lost outcome is not a fresh launch. Only a known non-clean result
        # may be recorded to fail closed after a partial/missing status.
        if not same and supervisor['phase']!='starting' and value['result'] not in DIRTY_RESULTS:fail('operation_conflict')
        if value['phase']=='running':
            if supervisor['phase'] not in {'starting','ready'} or not same and supervisor['phase']!='starting':fail('operation_conflict')
        if value['phase']=='stopped':self._require_stopped_api(launch)
        self._publish('launch-status.json','launch_status',value)
    @_broker_publication
    def publish_supervisor(self,value):
        self._assert(root=True);validate_record('supervisor',canonical(value))
        launch=self.read_launch()
        if value['supervisor']!=launch['supervisor'] or value['api']!=launch['api'] or value['clock_ticks_per_second']!=launch['clock_ticks_per_second']:fail('identity_mismatch')
        previous=self._read('supervisor.json','supervisor',optional=True)
        same=previous is not None and previous['supervisor']==value['supervisor'] and previous['api']==value['api']
        transitions={'starting':{'starting','ready','stopping','failed','stopped'},
            'ready':{'ready','stopping','failed','stopped'},'stopping':{'stopping','failed','stopped'},
            'failed':{'failed','stopping','stopped'},'stopped':{'stopped'}}
        if same and value['phase'] not in transitions[previous['phase']]:fail('operation_conflict')
        if not same and value['phase']!='starting':fail('operation_conflict')
        status=self.read_launch_status()
        matching=status is not None and all(status[k]==launch[k] for k in ('entrypoint','supervisor','api'))
        if value['phase']=='starting' and matching and status['phase']!='running':fail('operation_conflict')
        if value['phase']=='ready':
            if not matching or status['phase']!='running' or status['result']!='none':fail('operation_conflict')
        if value['phase']=='stopped':self._require_stopped_api(launch)
        self._publish('supervisor.json','supervisor',value)
    def _require_stopped_api(self,launch):
        if not proc_dead(launch['api']) or self.read_state()['state']!='disarmed' or self.read_seen() is not None or self.inventory():fail('operation_conflict')
        boot=self.read_boot()
        if boot is not None and boot['ready']:fail('operation_conflict')
    def publish_state(self,value):
        self._assert(root=True);validate_record('state',canonical(value))
        if value['state']=='armed' and self.read_launch()['readiness_profile']!=OBSERVED_READINESS_PROFILE:fail('operation_conflict')
        old=self._read('state.json','state',optional=True)
        if old is None:
            if value['state']!='disarmed' or value['disarmed']['reason']!='startup' or self.read_boot() is not None or self.read_seen() is not None:fail('state_inconsistent')
        elif old['state']=='armed':
            if value!=old and not (value['state']=='closing' and value['arm']==old['arm']):fail('operation_conflict')
        elif old['state']=='closing':
            if value['state']=='closing':
                if value['arm']!=old['arm'] or value['closing_reason'] not in {old['closing_reason'],'cancelled'}:fail('operation_conflict')
            elif value['state']=='disarmed':
                d=value['disarmed'];a=old['arm']
                if (self.read_seen() is not None or self.inventory() or d['operation_id']!=a['operation_id']
                        or d['runtime_boot_nonce']!=a['runtime_boot_nonce'] or d['api']!=a['api']
                        or d['reason']!=old['closing_reason'] or d['runtime']!={k:a[k] for k in ('container_id','started_at','image','resources_sha256')}):fail('state_inconsistent')
            else:fail('operation_conflict')
        elif value['state']=='armed':
            boot=self.read_boot();a=value['arm'];validate_supervision(self.read_supervisor())
            if (not boot or not boot['ready'] or boot['api']!=a['api'] or boot['runtime_boot_nonce']!=a['runtime_boot_nonce']
                    or boot['published_boottime_ns']>a['issued_boottime_ns'] or self.read_seen() is not None or self.inventory()
                    or old['disarmed']['operation_id']==a['operation_id']):fail('operation_conflict')
            check_fresh(a)
        elif value['state']!='disarmed':fail('operation_conflict')
        self._publish('state.json','state',value)
    def publish_boot(self,value):
        self._assert();validate_record('boot',canonical(value))
        launch=self.read_launch()
        if launch['readiness_profile']!=OBSERVED_READINESS_PROFILE:fail('operation_conflict')
        if value['api']!=launch['api'] or value['published_boottime_ns']<launch['exec_boottime_ns']:fail('identity_mismatch')
        if value['ready']:validate_launch_processes(launch,own_api=True)
        self._publish('boot.json','boot',value,api=True)
    def publish_seen(self,value):
        if self.read_launch()['readiness_profile']!=OBSERVED_READINESS_PROFILE:fail('operation_conflict')
        self._publish('seen.json','seen',value,api=True,exclusive=True)
    def inventory(self):
        self._assert();temps=[]
        folders=[(self._api,1800,0o600,{'boot.json','seen.json'},API_TEMPS,'api')]
        if self.role=='root':folders.append((self._parent,0,0o640,{'lock','supervisor.json','state.json','launch.json','launch-status.json','api'},ROOT_TEMPS,'root'))
        for directory,uid,mode,names,pattern,label in folders:
            listing_fd=os.open('.',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
            try:listing=os.listdir(listing_fd)
            finally:os.close(listing_fd)
            count=0
            for name in listing:
                if label=='root' and name=='api':continue
                if name not in names and not pattern.fullmatch(name):fail('custody_invalid')
                _regular(os.stat(name,dir_fd=directory,follow_symlinks=False),uid,mode,lock=name=='lock')
                if pattern.fullmatch(name):count+=1;temps.append(label+'/'+name)
            if count>1:fail('custody_invalid')
        return tuple(temps)
    def cleanup_observations(self,*,remove_boot=False):
        self._assert(root=True)
        if type(remove_boot) is not bool:fail('invalid_input')
        state=self.read_state()
        if state['state']=='armed':fail('operation_conflict')
        if remove_boot:
            # Cleanup identity comes ONLY from fully published root launch.
            # Missing/partial supervisor is not readiness and is never rebuilt.
            launch=self.read_launch();expected=launch['api']
            if not proc_dead(expected):fail('process_not_ready')
            try:supervisor=self._read('supervisor.json','supervisor',optional=True)
            except RouteCheckError as exc:
                if exc.code!='invalid_input':raise
                supervisor=None
            if supervisor is not None and (supervisor['api']!=expected
                    or supervisor['supervisor']!=launch['supervisor']
                    or supervisor['clock_ticks_per_second']!=launch['clock_ticks_per_second']):fail('identity_mismatch')
            try:boot=self.read_boot()
            except RouteCheckError as exc:
                # Only a malformed observation is discardable after PROVED
                # death. Descriptor/owner/mode/link/race failures still deny.
                if exc.code!='invalid_input':raise
                boot=None
            if boot is not None and boot['api']!=expected:fail('identity_mismatch')
        temps=self.inventory()
        for item in temps:
            where,name=item.split('/',1);os.unlink(name,dir_fd=self._parent if where=='root' else self._api)
        for name in ('seen.json',)+(('boot.json',) if remove_boot else ()):
            try:os.unlink(name,dir_fd=self._api)
            except FileNotFoundError:pass
        _sync(self._api);_sync(self._parent)
    def current_state(self):
        self._assert(root=True);temps=self.inventory();launch=self.read_launch();supervisor=self.read_supervisor();state=self.read_state();bad=bool(temps)
        try:boot=self.read_boot()
        except RouteCheckError:boot=None;bad=True
        try:seen=self.read_seen()
        except RouteCheckError:seen=None;bad=True
        slive=proc_live(supervisor['supervisor']);alive=proc_live(supervisor['api']);ready=False
        try:validate_supervision(supervisor,launch=launch);ready=bool(boot and boot['ready'] and boot['api']==supervisor['api'] and boot['published_boottime_ns']>=launch['exec_boottime_ns'])
        except RouteCheckError:pass
        arm=state['arm'];phase=state['state']
        if arm:
            try:check_fresh(arm)
            except RouteCheckError:phase='expired'
            if not boot or arm['runtime_boot_nonce']!=boot['runtime_boot_nonce'] or arm['api']!=supervisor['api']:bad=True
            if seen:
                try:validate_observation(arm,seen)
                except RouteCheckError:bad=True
                else:
                    if phase=='armed':phase='observed'
        elif seen:bad=True
        if bad or not alive or not slive:phase='stale';ready=False
        return record(supervisor=supervisor['supervisor'],supervisor_live=slive,api=supervisor['api'],api_live=alive,
            phase=supervisor['phase'],runtime_boot_nonce=boot['runtime_boot_nonce'] if boot else None,
            backend_ready=ready,active_operation_id=arm['operation_id'] if arm else None,
            active_runtime_boot_nonce=arm['runtime_boot_nonce'] if arm else None,active_api=arm['api'] if arm else None,
            state=phase,loaded_operation_id=boot['loaded_operation_id'] if boot else None,cleanup_required=bad)


class BrokerSession:
    """Original-process, single-use clean authority. Never serialize or recreate."""
    def __init__(self,launch,token=None):
        if token is not _SESSION_TOKEN:fail('operation_conflict')
        self._launch=json.loads(canonical(launch));self._key=_launch_key(launch)
        self._failure=None;self._request=None;self._reaped=None;self._wait_observation=None
        self._terminal=None;self._finishing=False;self._finished=False;self._publishing_progress=False;self._acknowledging_ready=False
    def __reduce__(self):raise TypeError('private broker session')
    def __copy__(self):raise TypeError('private broker session')
    def __deepcopy__(self,memo):raise TypeError('private broker session')
    @property
    def failure(self):return self._failure
    @property
    def operation_id(self):return None if self._terminal is None else self._terminal['operation_id']
    def _check(self,*,allow_finished=False):
        try:
            _original_broker(self._launch)
            if _BROKER_SESSIONS.get(self._key) is not self or self._finished and not allow_finished:fail('operation_conflict')
        except BaseException:
            # Callers may invoke this BEFORE their own guarded IO. Even a
            # transient authority-check failure permanently withholds clean.
            self.note_failure('publication_failed')
            raise
    def acknowledge_parent_ready(self):
        self._check()
        try:
            if self.failure is not None or self._request is not None or self._reaped is not None:fail('operation_conflict')
            if not parent_ready_condition():return False
            with locked_store(role='root') as store:
                if store.read_launch()!=self._launch:fail('identity_mismatch')
                validate_launch_processes(self._launch)
                sup=store.read_supervisor()
                if sup['phase']!='starting':fail('process_not_ready')
                store._require_profile_observations(self._launch)
                if not parent_ready_condition():fail('process_not_ready')
                status=store.read_launch_status()
                if status is None:store.publish_launch_status(self._status('running','none'))
                elif status['phase']!='running' or status['result']!='none':fail('state_inconsistent')
                self._acknowledging_ready=True
                try:store.publish_supervisor({**sup,'phase':'ready'})
                finally:self._acknowledging_ready=False
            return True
        except BaseException:self.note_failure('publication_failed');raise
    def clean_exit_code(self):
        # Final authority check is fallible and sticky, even after candidate
        # publication. Failure returns nonzero; actual termination still runs.
        try:self._check(allow_finished=True)
        except BaseException:return 70
        return 0 if self._finished and self.failure is None else 70
    def note_failure(self,reason):
        if reason not in SESSION_FAILURES:fail('invalid_input')
        # No fallible IO before the sticky latch. Forked/new callers cannot seal.
        if self._failure is None:self._failure=reason
    def reap_api(self,*,block=False):
        self._check()
        if self._reaped is not None:return self._reaped
        try:pid,status=os.waitpid(self._launch['api']['pid'],0 if block else os.WNOHANG)
        except BaseException:
            self.note_failure('cleanup_failed');raise
        if not pid:return None
        self._wait_observation=(pid,status)
        self.note_api_reaped(pid,status)
        return self._reaped
    def note_api_reaped(self,pid,wait_status):
        self._check()
        # Accept only THIS canonical session's actual kernel wait observation.
        # Delivery must use reap_api, never independently reap then pass a claim.
        if self._wait_observation!=(pid,wait_status) or self._reaped is not None:
            self.note_failure('cleanup_failed');fail('operation_conflict')
        self._wait_observation=None;self._reaped=(pid,wait_status)
        if not os.WIFEXITED(wait_status) or os.WEXITSTATUS(wait_status)!=0:self.note_failure('api_nonzero')
        elif self._request is None:self.note_failure('unexpected_api_exit')
    def register_controlled_request(self,kind):
        self._check()
        if kind not in {'stop','quiesce'}:fail('invalid_input')
        # Reap an already observable exit BEFORE registering any late request.
        if self.reap_api() is not None:
            if self._request is None:fail('operation_conflict')
            return
        self._request=kind
    def publish_status(self,value):
        self._check()
        try:
            with locked_store(role='root') as store:
                if store.read_launch()!=self._launch:fail('identity_mismatch')
                store.publish_launch_status(value)
        except BaseException:self.note_failure('publication_failed');raise
    def publish_supervisor(self,value):
        self._check()
        try:
            with locked_store(role='root') as store:
                if store.read_launch()!=self._launch:fail('identity_mismatch')
                store.publish_supervisor(value)
        except BaseException:self.note_failure('publication_failed');raise
    def _status(self,phase,result):
        return {'schema_version':1,'profile':LAUNCH_PROFILE,
            **{k:self._launch[k] for k in ('entrypoint','supervisor','api')},
            'phase':phase,'result':result,'updated_utc_ns':time.time_ns(),'updated_boottime_ns':boottime_ns()}
    def _dirty_result(self):
        return self._failure if self._failure in DIRTY_RESULTS else 'cleanup_failed'
    def publish_api_stopped(self):
        self._check()
        try:
            if self._reaped is None:fail('operation_conflict')
            with locked_store(role='root') as store:
                if store.read_launch()!=self._launch:fail('identity_mismatch')
                store._require_stopped_api(self._launch)
                if store.read_boot() is not None:fail('state_inconsistent')
                store.publish_supervisor({**store.read_supervisor(),'phase':'failed' if self.failure else 'stopping'})
                self._publishing_progress=True
                try:store.publish_launch_status(self._status('api_stopped',self._dirty_result() if self.failure else 'none'))
                finally:self._publishing_progress=False
        except BaseException:self.note_failure('publication_failed');raise
    def accept_terminal(self,frame):
        self._check()
        try:
            if self._terminal is not None:fail('operation_conflict')
            value=decode_terminal_frame(frame,launch=self._launch)
            self._terminal=value
            if value['result']!='success':self.note_failure('cleanup_failed')
        except BaseException:self.note_failure('terminal_channel_failed');raise
    def finish_clean(self):
        self._check()
        try:
            if (self.failure is not None or self._request is None or self._reaped is None
                    or not os.WIFEXITED(self._reaped[1]) or os.WEXITSTATUS(self._reaped[1])!=0
                    or self._terminal is None or self._terminal['result']!='success'):fail('operation_conflict')
            with locked_store(role='root') as store:
                if store.read_launch()!=self._launch:fail('identity_mismatch')
                if store.read_api_stop_progress() is None:fail('state_inconsistent')
                self._finishing=True
                try:
                    value=self._status('stopped','clean_stop');store.publish_launch_status(value)
                    store.publish_supervisor({**store.read_supervisor(),'phase':'stopped'})
                finally:self._finishing=False
            self._finished=True
            # Exact ACKNOWLEDGED status bytes, still merely a candidate until
            # original broker exit0/PID1 wait/log producer/current host proof.
            return canonical(value)
        except BaseException:self.note_failure('publication_failed');raise


def broker_session(launch):
    validate_record('launch',canonical(launch));_original_broker(launch)
    key=_launch_key(launch)
    if key in _BROKER_SESSIONS:fail('operation_conflict')
    parent_ready_condition(require_absent=True)
    with locked_store(role='root') as store:
        if store.read_launch()!=launch:fail('identity_mismatch')
        validate_launch_processes(launch)
    session=BrokerSession(launch,_SESSION_TOKEN);_BROKER_SESSIONS[key]=session
    return session


def _sync(pathfd):
    fd=os.open('.',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=pathfd)
    try:os.fsync(fd)
    finally:os.close(fd)


@contextmanager
def locked_store(*,role):
    """Yield fixed-method store; <=2s lock wait. No caller-selected root/path."""
    if role not in {'api','root'} or os.geteuid()!=(1800 if role=='api' else 0):fail('custody_invalid')
    parent=api=lock=None;store=None
    try:
        parent=_open_parent();api=os.open('api',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        _directory(api,1800,1800,0o700)
        lock=os.open('lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        before=os.fstat(lock);_regular(before,0,0o640,lock=True);deadline=time.monotonic()+2
        while True:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);break
            except BlockingIOError:
                if time.monotonic()>=deadline:fail('process_not_ready')
                time.sleep(0.01)
        if _identity(before)!=_identity(os.fstat(lock)) or _identity(before)!=_identity(os.stat('lock',dir_fd=parent,follow_symlinks=False)):fail('custody_invalid')
        current=_open_parent()
        try:
            if os.fstat(current).st_ino!=os.fstat(parent).st_ino or os.fstat(current).st_dev!=os.fstat(parent).st_dev:fail('custody_invalid')
        finally:os.close(current)
        store=_Store(role,parent,api);store.inventory();yield store
    except OSError:fail('custody_invalid')
    finally:
        if store:store._valid=False
        for fd in (lock,api,parent):
            if fd is not None:os.close(fd)


def bootstrap_store():
    """Root-only directory/lock creation; never replaces an existing lock/record."""
    if os.geteuid()!=0:fail('custody_invalid')
    # Parent components must be existing directories, not symlinks.
    parent=os.open('/',os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for part in DIRECTORY.parts[1:-1]:
            child=os.open(part,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);os.close(parent);parent=child
        try:
            os.mkdir(DIRECTORY.name,0o710,dir_fd=parent);os.chown(DIRECTORY.name,0,1800,dir_fd=parent,follow_symlinks=False);os.chmod(DIRECTORY.name,0o710,dir_fd=parent,follow_symlinks=False)
        except FileExistsError:pass
        root=_open_parent()
        try:
            try:os.mkdir('api',0o700,dir_fd=root);os.chown('api',1800,1800,dir_fd=root,follow_symlinks=False)
            except FileExistsError:pass
            try:
                fd=os.open('lock',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o640,dir_fd=root)
            except FileExistsError:pass
            else:
                try:os.fchown(fd,0,1800);os.fchmod(fd,0o640);os.fsync(fd)
                finally:os.close(fd)
            _sync(root)
        finally:os.close(root)
    except OSError:fail('custody_invalid')
    finally:os.close(parent)
    # Validate existing custody too; do not initialize any authoritative record.
    with locked_store(role='root'):pass


def validate_observation(arm,seen):
    if (seen['operation_id']!=arm['operation_id'] or seen['runtime_boot_nonce']!=arm['runtime_boot_nonce']
            or seen['api']!=arm['api'] or seen['challenge_sha256']!=hashlib.sha256(arm['challenge'].encode()).hexdigest()
            or not arm['issued_boottime_ns']<=seen['observed_boottime_ns']<=arm['expires_boottime_ns']
            or not arm['issued_utc_ns']-2_000_000_000<=seen['observed_utc_ns']<=arm['expires_utc_ns']):fail('observation_missing')



RECOVERY_PROFILE = 'volt_local_recovery_v1'
START_FIELDS = BASE|{'document_type','installation_id','journal_id','restore_generation',
    'recovery_epoch_id','image_id','resources_sha256','initial_preparation','local_auth_config_sha256'}


def _validate_start_admission(value):
    _obj_base(value,RECOVERY_PROFILE);_obj(value,START_FIELDS)
    if value['document_type']!='local_start_admission_v2' or type(value['initial_preparation']) is not bool:fail('invalid_input')
    for key in ('installation_id','journal_id'):_uuid(value[key])
    _int(value['restore_generation'])
    if value['restore_generation']==0:
        if value['recovery_epoch_id'] is not None:fail('invalid_input')
    else:
        _uuid(value['recovery_epoch_id'])
        if value['initial_preparation']:fail('invalid_input')
    _text(value['image_id'],r'sha256:[0-9a-f]{64}');_text(value['resources_sha256'],r'[0-9a-f]{64}')
    _text(value['local_auth_config_sha256'],r'[0-9a-f]{64}')


def _fixed_private_read(path,owner,limit=16384):
    """Internal fixed root-admission reads; not a caller-selectable file API."""
    parent=os.open('/',os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for component in path.parts[1:-1]:
            child=os.open(component,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            os.close(parent);parent=child
        fd=os.open(path.name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            before=os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid!=owner or stat.S_IMODE(before.st_mode)!=0o600
                    or before.st_nlink!=1 or before.st_size>limit):fail('custody_invalid')
            raw=os.read(fd,limit+1)
            if len(raw)!=before.st_size or _identity(before)!=_identity(os.fstat(fd)) or _identity(before)!=_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)):fail('custody_invalid')
            return raw
        finally:os.close(fd)
    finally:os.close(parent)


def _fixed_live_fence(owner):
    directory=Path('/run/volt-restore-fence')
    parent=os.open('/',os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for component in directory.parts[1:]:
            child=os.open(component,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            os.close(parent);parent=child
        _directory(parent,owner,1800,0o710)
        fd=os.open('fence.json',os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            before=os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid!=owner or before.st_gid!=1800
                    or stat.S_IMODE(before.st_mode)!=0o640 or before.st_nlink!=1 or before.st_size>16384):fail('custody_invalid')
            raw=os.read(fd,16385)
            if len(raw)!=before.st_size or _identity(before)!=_identity(os.fstat(fd)) or _identity(before)!=_identity(os.stat('fence.json',dir_fd=parent,follow_symlinks=False)):fail('custody_invalid')
            _directory(parent,owner,1800,0o710)
            return raw
        finally:os.close(fd)
    finally:os.close(parent)


def _read_local_start_admission():
    """Fixed early issuer/custody join; no release or main-start authority."""
    if os.geteuid()!=0:fail('custody_invalid')
    try:
        config=json.loads(_fixed_private_read(Path('/etc/volt/local-recovery.json'),1800),object_pairs_hook=_pairs)
        fields={'schema_version','profile','installation_id','issuer_key_id','operator_key_id','operator_id',
            'issuer_public_key_file','issuer_private_key_file','operator_public_key_file','material_key_file',
            'restore_fence_file','restore_fence_custody','proof_store'}
        _obj(config,fields);_obj_base(config,RECOVERY_PROFILE)
        _uuid(config['installation_id']);custody=config['restore_fence_custody'];_obj(custody,{'owner_uid','runtime_gid'})
        _int(custody['owner_uid'],0,2**32-1)
        if type(custody['runtime_gid']) is not int or custody['runtime_gid']!=1800 or config['restore_fence_file']!='/run/volt-restore-fence/fence.json':fail('identity_mismatch')
        start=Path('/run/volt-start-admission');info=start.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=custody['owner_uid'] or stat.S_IMODE(info.st_mode)!=0o700:fail('custody_invalid')
        value=validate_record('start_admission',_fixed_private_read(start/'admission.json',custody['owner_uid']))
        fence=json.loads(_fixed_live_fence(custody['owner_uid']),object_pairs_hook=_pairs)
        expected={key:value[key] for key in ('schema_version','profile','installation_id','journal_id','restore_generation','recovery_epoch_id')}
        if (type(fence) is not dict or set(fence)!=set(expected) or any(type(fence[k]) is not type(v) or fence[k]!=v for k,v in expected.items())
                or config['installation_id']!=value['installation_id']):fail('identity_mismatch')
        return value
    except (OSError,ValueError,TypeError,KeyError,UnicodeError):fail('custody_invalid')


def _read_released_local_admission():
    """Released main guard; never permits an initial/unreleased record."""
    value=_read_local_start_admission()
    try:
        if value['initial_preparation']:fail('identity_mismatch')
        released=validate_record('start_admission',_fixed_private_read(Path('/run/uvm-maintenance/host-start-release.json'),0))
        if released!=value:fail('identity_mismatch')
        return value
    except (OSError,ValueError,TypeError,KeyError,UnicodeError):fail('custody_invalid')


def validate_local_config(config):
    """Pure shared existing local config shape/ingress validation, no key/DB/env IO."""
    keys = {"schema_version", "installation_id", "public_origin", "secret_source",
        "bootstrap_delivery", "session_policy", "trusted_ingress"}
    if not isinstance(config, dict) or set(config) != keys or config.get("schema_version") != 1:
        raise ValueError("local authentication configuration schema is invalid")
    try:
        config["installation_id"] = str(uuid.UUID(config["installation_id"]))
        origin = urlsplit(config["public_origin"])
        if (origin.scheme not in {"http", "https"} or not origin.hostname or not origin.netloc or origin.path not in ("", "/")
                or origin.query or origin.fragment):
            raise ValueError
        ingress = config["trusted_ingress"]
        if not isinstance(ingress, dict):
            raise ValueError
        loopback = origin.hostname in {"localhost", "127.0.0.1", "::1"}
        if ingress.get("mode") == "loopback" and not (origin.scheme == "http" and loopback):
            raise ValueError
        if ingress.get("mode") == "https" and origin.scheme != "https":
            raise ValueError
        if (not isinstance(config["secret_source"], dict) or set(config["secret_source"]) !=
                {"kind", "secret_source_id", "key_path"} or config["secret_source"]["kind"] != "encrypted_local_v1"):
            raise ValueError
        config["secret_source"]["secret_source_id"] = str(uuid.UUID(config["secret_source"]["secret_source_id"]))
        delivery = config["bootstrap_delivery"]
        if not isinstance(delivery, dict) or set(delivery) != {"kind", "path"} or delivery["kind"] != "private_file":
            raise ValueError
        if not isinstance(config["session_policy"], dict) or set(config["session_policy"]) != {"ttl_seconds"}:
            raise ValueError
        ttl = config["session_policy"]["ttl_seconds"]
        if type(ttl) is not int or ttl != 3600:
            raise ValueError
        ingress = config["trusted_ingress"]
        if (set(ingress) != {"mode", "allowed_hosts", "allowed_peer_cidrs"}
                or ingress["mode"] not in {"loopback", "https"} or not isinstance(ingress["allowed_hosts"], list)
                or not ingress["allowed_hosts"] or any(not isinstance(host, str) or not host for host in ingress["allowed_hosts"])
                or not isinstance(ingress["allowed_peer_cidrs"], list) or not ingress["allowed_peer_cidrs"]
                or any(not isinstance(cidr, str) or not cidr for cidr in ingress["allowed_peer_cidrs"])):
            raise ValueError
        if origin.hostname not in {host.lower().split(":", 1)[0] for host in ingress["allowed_hosts"]}:
            raise ValueError
    except (ValueError, TypeError, KeyError, OSError):
        raise ValueError("local authentication configuration schema is invalid") from None
    return config


def _open_config_parent(path):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            try:
                info=os.fstat(child)
                if info.st_uid!=0 or stat.S_IMODE(info.st_mode)&0o022:fail('custody_invalid')
            except BaseException:os.close(child);raise
            os.close(fd);fd=child
        return fd
    except BaseException:os.close(fd);raise


def _read_config_file(path,*,source):
    parent=_open_config_parent(path)
    try:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        try:
            before=os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode)!=0o600
                    or before.st_nlink!=1 or not 1<=before.st_size<=16384
                    or not source and (before.st_uid,before.st_gid)!=(1800,1800)):fail('custody_invalid')
            if source and not os.fstatvfs(fd).f_flag&os.ST_RDONLY:fail('custody_invalid')
            raw=os.read(fd,16385)
            if (len(raw)!=before.st_size or _identity(before)!=_identity(os.fstat(fd))
                    or _identity(before)!=_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False))):fail('custody_invalid')
            return raw
        finally:os.close(fd)
    finally:os.close(parent)


def _read_local_config_pair():
    if os.geteuid()!=0:fail('custody_invalid')
    try:
        source=_read_config_file(LOCAL_CONFIG_SOURCE,source=True)
        if _read_config_file(LOCAL_CONFIG_STAGE,source=False)!=source:fail('identity_mismatch')
        config=validate_local_config(json.loads(source,object_pairs_hook=_pairs))
        return source,config
    except (OSError,ValueError,TypeError,KeyError,UnicodeError):fail('custody_invalid')


def _check_admitted_local_config(value,raw,config):
    if (config['installation_id']!=value['installation_id']
            or hashlib.sha256(raw).hexdigest()!=value['local_auth_config_sha256']):fail('identity_mismatch')


def load_start_admission(*,expected_image_id,expected_resources_sha256):
    """ROOT-only early readonly start check, including admitted initial gen0.

    No release requirement, no skip flag/writer. Does not authorize main READY;
    existing maintenance/ACK/release protocol still precedes normal main launch.
    """
    _text(expected_image_id,r'sha256:[0-9a-f]{64}');_text(expected_resources_sha256,r'[0-9a-f]{64}')
    value=_read_local_start_admission()
    if value['image_id']!=expected_image_id or value['resources_sha256']!=expected_resources_sha256:fail('identity_mismatch')
    raw,config=_read_local_config_pair();_check_admitted_local_config(value,raw,config)
    return value


def load_runtime_admission(*,expected_image_id,expected_resources_sha256):
    """Root-control released reader, explicit independent image/resource witnesses."""
    _text(expected_image_id,r'sha256:[0-9a-f]{64}');_text(expected_resources_sha256,r'[0-9a-f]{64}')
    value=_read_released_local_admission()
    if value['image_id']!=expected_image_id or value['resources_sha256']!=expected_resources_sha256:fail('identity_mismatch')
    raw,config=_read_local_config_pair();_check_admitted_local_config(value,raw,config)
    return value


def derive_launch_readiness(admitted_bootstrap):
    """Original protected MAIN producer only; no env defaults or mode selector.

    Full exact API-environment whitelist validation belongs to the fixed launcher
    before this call; here its explicit readiness/composition fields are checked.
    Normal main parent has already performed existing image/resource start check.
    """
    if os.geteuid()!=0:fail('custody_invalid')
    try:
        _obj(admitted_bootstrap,BASE|{'main_bind','main_port','api_environment'})
        _obj_base(admitted_bootstrap,LAUNCH_PROFILE)
        _int(admitted_bootstrap['main_port'],1,65535)
        if type(admitted_bootstrap['main_bind']) is not str or not admitted_bootstrap['main_bind']:fail('invalid_input')
        env=admitted_bootstrap['api_environment']
        if type(env) is not dict or any(type(k) is not str or type(v) is not str for k,v in env.items()):fail('invalid_input')
        auth=env['UVM_AUTH_MODE'];verification=env['UVM_G7_VERIFICATION_ONLY']
        if (auth not in {'local','oidc','bearer'} or verification not in {'0','1'}
                or 'UVM_G7_RECOVERY_CONTROL_ONLY' in env
                or env['UVM_API_HOST']!=admitted_bootstrap['main_bind']
                or env['UVM_API_PORT']!=str(admitted_bootstrap['main_port'])
                or env['UVM_OIDC_DEPLOYMENT_MODE'] not in {'local','external','demo'}):fail('invalid_input')
        prefix='verification' if verification=='1' else 'normal'
        if auth!='local':return prefix+'_'+auth
        if (env['UVM_LOCAL_AUTH_CONFIG_FILE']!='/etc/volt/local-auth.json'
                or env['UVM_OIDC_DEPLOYMENT_MODE']!='local'):fail('invalid_input')
        raw,config=_read_local_config_pair()
        if verification=='0':_check_admitted_local_config(_read_released_local_admission(),raw,config)
        if config['trusted_ingress']['mode']=='https':_origin(config['public_origin']);mode='https'
        else:mode='loopback'
        return prefix+'_local_'+mode
    except (ValueError,TypeError,KeyError,UnicodeError):fail('invalid_input')


def validate_local_backup_profile(launch):
    """Purpose guard ONLY: caller still owes installation/custody/clean stop proof."""
    validate_record('launch',canonical(launch))
    if launch['readiness_profile'] not in LOCAL_BACKUP_PROFILES:fail('operation_conflict')
    return launch['readiness_profile']
