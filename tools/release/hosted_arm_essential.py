"""Hosted native ARM LOCAL journey adapter; no signer or trust bypass.

Run only after independently checked native artifacts, genuine ephemeral log,
fixture Q and signed two-child graph exist. No infrastructure is started here.
The artifact/runtime source P and this adapter R remain distinct evidence fields.
"""
from __future__ import annotations
from contextlib import contextmanager
import argparse,hashlib,importlib.util,json,os,platform,re,subprocess,sys
from pathlib import Path

PROFILE='hosted_native_arm_essential_v1'
PLATFORM='linux/arm64'
DIGEST=re.compile(r'sha256:[0-9a-f]{64}')
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
DB_COMMIT='0362d55869965067c9ffa276a78d18e95a596ca3'
DB_FILES={
 'examples/deployment/docker/db_server/Dockerfile':'309f8cdf76182318f1bed0d8a540aa95d69b3adfbe10e29a7fecae23df230cd4',
 'examples/deployment/docker/db_server/mysql.cnf':'84ada2681e8e52fea554ea3940cf3ea06d87c41a173ebfb8e2482a02fc94abac',
 'storage/mysql/schema/storage.sql':'58c9d1c5cc093eb33fb3bf05e3ab05ba053ef1ae0a5584cbd6cda69307aaef63'}

def pairs(rows):
    result={}
    for k,v in rows:
        if k in result:raise ValueError('duplicate request field')
        result[k]=v
    return result

def validate_request(value,stage):
    common={'schema_version','profile','source_revision','source_snapshot','source_checkout','evidence'}
    if stage not in ('prepare-db-context','build-q','essential'):raise ValueError('fixed stage required')
    fields=common|({'db_source_directory'}if stage=='prepare-db-context'else {'public_policy','public_policy_sha256'}if stage=='build-q'else{'bundle','fixture','image_id','private'})
    if (type(value)is not dict or set(value)!=fields or type(value['schema_version'])is not int
            or value['schema_version']!=1 or value['profile']!=PROFILE
            or type(value['source_revision'])is not str or re.fullmatch('[0-9a-f]{40}',value['source_revision'])is None
            or type(value['source_snapshot'])is not str or DIGEST.fullmatch(value['source_snapshot'])is None):raise ValueError('closed source-bound request required')
    names=()if stage=='prepare-db-context'else('public_policy_sha256',)if stage=='build-q'else('image_id',)
    if any(type(value[k])is not str or DIGEST.fullmatch(value[k])is None for k in names):raise ValueError('exact expected digest required')
    path_fields=('source_checkout','evidence','db_source_directory')if stage=='prepare-db-context'else('source_checkout','evidence','public_policy')if stage=='build-q'else('source_checkout','evidence','bundle','fixture','private')
    for name in path_fields:
        if type(value[name])is not str or not value[name].startswith('/')or '\x00'in value[name]:raise ValueError('absolute owned input paths required')
    source_path=Path(value['source_checkout']).resolve(strict=False)
    for name in ('evidence','private')if stage=='essential'else('evidence',):
        target=Path(value[name]).resolve(strict=False)
        if target==source_path or source_path in target.parents or target in source_path.parents:raise ValueError('private output must not overlap source')
    if Path(value['evidence']).exists():raise ValueError('fresh evidence directory required')
    if stage=='essential'and Path(value['private']).exists():raise ValueError('fresh private fixture required')
    return value

def read_request(path,expected,stage):
    # Import reviewed bounded nofollow reader; no policy or image admission here.
    from tools.release.native_runtime_probe import regular_bytes
    if not DIGEST.fullmatch(expected):raise ValueError('independent request digest required')
    raw=regular_bytes(path,16384)
    if 'sha256:'+hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('request differs from independent expected bytes')
    return validate_request(json.loads(raw,object_pairs_hook=pairs),stage)

def source_binding(value):
    source=Path(value['source_checkout'])
    if source.resolve(strict=True)!=source or not source.is_dir():raise ValueError('canonical source checkout required')
    revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()
    if revision!=value['source_revision']or subprocess.check_output(['git','status','--porcelain'],cwd=source,text=True):raise ValueError('clean selected source required')
    archive=subprocess.check_output(['git','archive','--format=tar',revision],cwd=source)
    if 'sha256:'+hashlib.sha256(archive).hexdigest()!=value['source_snapshot']:raise ValueError('complete source archive differs')
    # No tracked source overlay, generated signer, or policy enters P/U.
    return source

def q_command(value):
    return [sys.executable,str(Path(value['source_checkout'])/'tools/release/build_native_fixture_verifier.py'),
        '--platform',PLATFORM,'--source-commit',value['source_revision'],'--source-snapshot',value['source_snapshot'],
        '--public-policy',value['public_policy'],'--expected-policy-sha256',value['public_policy_sha256'],
        '--evidence',value['evidence']]

def prepare_db_context(directory,output):
    from tools.release.native_runtime_probe import regular_bytes
    directory=directory.absolute()
    if directory.resolve(strict=True)!=directory:raise ValueError('canonical upstream source required')
    files={}
    for name,expected in DB_FILES.items():
        path=directory/name
        if path.resolve(strict=True)!=path:raise ValueError('upstream path alias')
        raw=regular_bytes(path,1024*1024)
        if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('exact canonical DB source differs')
        files[name]=raw
    if output.exists()or output.resolve(strict=False)!=output.absolute():raise ValueError('new canonical output required')
    output.mkdir(mode=0o700)
    for name,raw in files.items():
        path=output/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with path.open('xb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
    (output/'preparation.json').write_text(json.dumps({'upstream_commit':DB_COMMIT,'files':DB_FILES,
        'scope':'public canonical DB context only; no build/native execution/signing or trust claim'},indent=2)+'\n')


def require_native():
    if platform.machine()!='aarch64':raise ValueError('native ARM64 host required before Docker')
    # Docker's explicit context overrides DOCKER_HOST. Resolve only local
    # metadata first, then pin the validated socket for every descendant CLI.
    context=os.environ.get('DOCKER_CONTEXT')
    endpoint=os.environ.get('DOCKER_HOST')
    if context or not endpoint:
        if not context:
            selected=subprocess.run(['docker','context','show'],capture_output=True,text=True,timeout=30)
            if selected.returncode:raise ValueError('local Docker context required')
            context=selected.stdout.strip()
        selected=subprocess.run(['docker','context','inspect',context,'--format','{{(index .Endpoints "docker").Host}}'],capture_output=True,text=True,timeout=30)
        if selected.returncode:raise ValueError('local Docker endpoint required')
        endpoint=selected.stdout.strip()
    if not endpoint.startswith('unix:///')or any(c.isspace()or ord(c)<32 for c in endpoint)or '?'in endpoint or '#'in endpoint:
        raise ValueError('local Unix Docker endpoint required before daemon contact')
    os.environ.pop('DOCKER_CONTEXT',None)
    os.environ['DOCKER_HOST']=endpoint
    r=subprocess.run(['docker','version','--format','{{.Server.Os}}/{{.Server.Arch}}'],capture_output=True,text=True,timeout=30)
    if r.returncode or r.stdout.strip()!=PLATFORM:raise ValueError('native ARM64 daemon required')

# Closed public diagnostic labels. Unknown private helper names never escape.
JOURNEY_STAGES={
 'fixture-installer-bundle-signature':'bundle-signature',
 'fixture-verifier-signature':'verifier-signature',
 'fixture-verifier-provenance':'verifier-provenance',
 'fixture-runtime-pull':'runtime-pull','fixture-runtime-inspect':'runtime-inspect',
 'native-engine-platform':'native-engine','fixture-runtime-index':'runtime-index',
 'fixture-full-runtime-admission':'full-graph-admission',
 'focused-trusted-launcher-signature':'launcher-signature',
 'focused-public-install':'public-install','focused-public-cold-stop':'public-cold-stop',
 'focused-public-backup':'public-backup','focused-public-destroy-before-restore':'destroy-before-restore',
 'focused-external-verify-before-extract':'verify-before-extract',
 'focused-instance-extract':'instance-extract','focused-public-restore-provision':'restore-provision',
 'focused-state-corruption':'negative-state-corruption',
 'focused-remove-state-corruption':'negative-state-restoration',
 'focused-public-valid-admit':'valid-admit',
 'essential-restored-public-start':'restored-start','essential-restored-public-stop':'restored-stop'}

# Diagnostic matching ONLY: these existing error strings confer no admission.
ADMISSION_ERRORS={
 'verification input is missing or is not a regular file':'input-file',
 'installer bundle is missing, unsafe, or exceeds the archive size limit':'bundle-input',
 'installer archive member count is outside the closed inventory bound':'bundle-inventory',
 'installer archive contains duplicate members':'bundle-inventory',
 'installer archive contains unsafe path, type, or member size':'bundle-inventory',
 'installer archive contains duplicate inventory names':'bundle-inventory',
 'installer archive member content is missing':'bundle-inventory',
 'installer archive member content exceeds its declared bound':'bundle-inventory',
 'installer archive inventory is not the closed RC4 inventory':'bundle-inventory',
 'installer bundle manifest is invalid JSON':'bundle-manifest',
 'local fixture bundle does not bind its independently pinned verifier image':'bundle-verifier-binding',
 'installer bundle manifest, version, source inventory, or runtime reference mismatch':'bundle-manifest',
 'fixture verifier trust material is incomplete':'fixture-policy',
 'fixture Cosign operation is not in the closed verification allowlist':'fixture-policy',
 'Docker runtime inspection is not valid JSON':'runtime-inspection',
 'Docker runtime inspection must identify exactly one image':'runtime-inspection',
 'selected runtime platform differs from the admitted engine platform':'runtime-platform',
 'selected runtime image has no immutable configuration ID':'runtime-identity',
 'runtime labels do not match the signed source and local-install contract':'runtime-labels',
 'runtime index bytes do not match the signed immutable reference':'runtime-index',
 'runtime reference is not a supported OCI image index':'runtime-index',
 'runtime index must have exactly one supported Linux amd64 and arm64 child':'runtime-index',
 'runtime platform descriptor digest is malformed':'runtime-index',
 'runtime index is missing a supported platform child':'runtime-index',
 'verified runtime provenance output is not JSON':'runtime-provenance',
 'verified runtime provenance output has no attestations':'runtime-provenance',
 'runtime requires exactly one supported signed provenance statement':'runtime-provenance',
 'signed runtime provenance does not bind source, version, index and exact platform children':'runtime-provenance',
 'registry redirect refused during child admission':'child-registry',
 'fixture child registry is not the owned loopback registry':'child-registry',
 'registry child request failed closed':'child-registry',
 'registry child document too large':'child-registry',
 'registry child digest invalid':'child-descriptor',
 'registry child size invalid':'child-descriptor',
 'actual child/config bytes differ from signed digest':'child-bytes',
 'registry child document invalid':'child-bytes',
 'signed child media type differs':'child-descriptor',
 'actual platform child is not an executable image manifest':'child-descriptor',
 'actual platform config differs from signed source/platform contract':'child-config',
 'actual platform config media type unsupported':'child-config',
 'selected Docker config/descriptor ID differs from signed platform child':'selected-child-binding',
 'full graph verification requires reference, source, version, and platform metadata':'invocation',
 'full graph verification requires image inspection, index, and output paths':'invocation'}

def admission_error_class(raw):
    """Classify a bounded original stderr, never return its dynamic content.

    This is a matched diagnostic, not authenticated causal evidence or authority.
    Unknown, duplicate, unterminated or unsupported text yields no classification.
    """
    if type(raw)is not bytes or len(raw)>65536 or not raw.endswith(b'\n'):return 'unclassified'
    try:text=raw.decode('ascii')
    except UnicodeDecodeError:return 'unclassified'
    if any(ord(c)<32 and c not in '\n\t'for c in text):return 'unclassified'
    prefix='verifier.py: error: '
    rows=[line for line in text.split('\n')if line.startswith(prefix)]
    if len(rows)!=1:return 'unclassified'
    message=rows[0][len(prefix):]
    if message in ADMISSION_ERRORS:return ADMISSION_ERRORS[message]
    if message.startswith('local fixture transparency verification failed: '):return 'fixture-transparency'
    return 'unclassified'

def retained_admission_error(evidence):
    from tools.release.native_runtime_probe import regular_bytes
    try:return admission_error_class(regular_bytes(Path(evidence)/'fixture-full-runtime-admission.stderr',65536))
    except (OSError,ValueError):return 'unclassified'

INSTALL_PHASES=frozenset(('host-preflight','verifier-fetch','bundle-discovery','runtime-fetch',
 'runtime-observation','online-full-graph','cache-stage','original-cache-export','runtime-identity',
 'package-extraction','argument-validation','resource-creation','initial-request','initial-admission',
 'exclusive-lock','cache-publication','custody-prepare','journal-read','custody-validation',
 'resource-validation','compose-validation','api-prepare','api-start','api-release','health',
 'capability-delivery','final-owner-check','final-report','completed'))

def install_phase_receipt(raw):
    """Read ONE source-produced closed record, not an error phrase matcher.

    Diagnostic only. Status is the original shell exit BEFORE unchanged cleanup,
    so it can differ from the caller result if cleanup subsequently failed.
    """
    if type(raw)is not bytes or len(raw)>1024*1024:return None
    prefix=b'VOLT_FIXTURE_INSTALL_RECEIPT '
    rows=[line for line in raw.splitlines(keepends=True)if line.startswith(prefix)]
    if len(rows)!=1 or not rows[0].endswith(b'\n')or len(rows[0])>512:return None
    try:
        encoded=rows[0][len(prefix):-1];record=json.loads(encoded.decode('ascii'),object_pairs_hook=pairs)
        if (type(record)is not dict or set(record)!={'phase','profile','status'}
                or record['profile']!='volt_fixture_install_exit_v1'
                or type(record['phase'])is not str or record['phase']not in INSTALL_PHASES
                or type(record['status'])is not int or not 0<=record['status']<=255
                or json.dumps(record,sort_keys=True,separators=(',',':')).encode()!=encoded):return None
    except (ValueError,UnicodeDecodeError):return None
    return record

def retained_install_receipt(evidence):
    from tools.release.native_runtime_probe import regular_bytes
    try:return install_phase_receipt(regular_bytes(Path(evidence)/'focused-public-install.stderr',1024*1024))
    except (OSError,ValueError):return None

HEALTH_CAUSES=frozenset(('owner-before-poll','owner-after-healthy','unhealthy','wait-budget'))
def health_phase_receipt(raw):
    if type(raw)is not bytes or len(raw)>1024*1024:return None
    prefix=b'VOLT_FIXTURE_HEALTH_RECEIPT '
    lines=[line for line in raw.splitlines(keepends=True)if line.startswith(prefix)]
    if len(lines)!=1 or not lines[0].endswith(b'\n')or len(lines[0])>512:return None
    try:
        encoded=lines[0][len(prefix):-1];r=json.loads(encoded.decode('ascii'),object_pairs_hook=pairs)
        if (type(r)is not dict or set(r)!={'profile','pass','cause'}or r['profile']!='volt_fixture_health_exit_v1'
                or r['pass']not in ('closed','configured')or r['cause']not in HEALTH_CAUSES
                or json.dumps(r,sort_keys=True,separators=(',',':')).encode()!=encoded):return None
        return r
    except (ValueError,UnicodeDecodeError,TypeError):return None

# Fixed metadata-only projection: raw Health.Log.Output/config/env never enters
# this subprocess stream. The daemon retains at most five health log entries.
HEALTH_INSPECT_TEMPLATE='{"id":{{json .Id}},"name":{{json .Name}},"created":{{json .Created}},"image":{{json .Image}},"reference":{{json .Config.Image}},"owner":{{json (index .Config.Labels "volt.compose.owner-token")}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}},"snapshot":{{json (index .Config.Labels "org.volt.compose.source-snapshot")}},"started":{{json .State.StartedAt}},"status":{{json .State.Status}},"exit":{{json .State.ExitCode}},"oom":{{json .State.OOMKilled}},"restarting":{{json .State.Restarting}},"restarts":{{json .RestartCount}},"health":{{if .State.Health}}{"status":{{json .State.Health.Status}},"streak":{{json .State.Health.FailingStreak}},"logs":[{{range $i,$l:=.State.Health.Log}}{{if $i}},{{end}}{"exit":{{json $l.ExitCode}},"start":{{json $l.Start}},"end":{{json $l.End}}}{{end}}]}{{else}}null{{end}}}'

def failed_health_projection(value,evidence):
    """Failure-only observation. No adoption, lifecycle command or authority."""
    from tools.release.native_runtime_probe import regular_bytes
    unavailable={'status':'unavailable'}
    try:
        root=Path(value['private'])/'instance';journal=root/'instance.json'
        original=regular_bytes(journal,1024*1024);info=json.loads(original,object_pairs_hook=pairs)
        # Reuse the original successful independently verified graph result,
        # never derive image/source expectations from the candidate journal.
        if regular_bytes(Path(evidence)/'fixture-full-runtime-admission.exit',8)!=b'0\n':return unavailable
        runtime=json.loads(regular_bytes(Path(evidence)/'fixture-full-runtime-admission.stdout',65536),object_pairs_hook=pairs)['runtime']
        if (runtime['image_id']!=value['image_id']or runtime['source_revision']!=value['source_revision']
                or runtime['source_snapshot']!=value['source_snapshot']or runtime['platform']!=PLATFORM):return unavailable
        owner=info['owner_token'];project=info['project'];admitted=info['image_admission']
        if (type(owner)is not str or not re.fullmatch('[0-9a-f]{64}',owner)
                or project!='volt-easy-delivery-'+owner[:12]or info['mode']!='local'or info['platform']!=PLATFORM
                or admitted['id']!=runtime['image_id']or admitted['source_revision']!=value['source_revision']
                or admitted['source_snapshot']!=value['source_snapshot']):return unavailable
        def inspect(target):
            r=subprocess.run(['docker','container','inspect',target,'--format',HEALTH_INSPECT_TEMPLATE],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=2)
            if r.returncode or len(r.stdout)>16384:raise ValueError('diagnostic unavailable')
            row=json.loads(r.stdout,object_pairs_hook=pairs)
            if (not re.fullmatch('[0-9a-f]{64}',row['id'])or row['name']!='/'+project+'-volt-1'
                    or row['owner']!=owner or row['project']!=project or row['image']not in(runtime['image_id'],runtime['image_config_id'])
                    or row['reference']!='127.0.0.1:46150/volt@'+runtime['image_index_digest']
                    or row['revision']!=value['source_revision']or row['snapshot']!=value['source_snapshot']):raise ValueError('identity unavailable')
            return row
        before=inspect(project+'-volt-1');after=inspect(before['id'])
        keys=('id','name','created','image','reference','owner','project','revision','snapshot','started')
        if any(before[k]!=after[k]for k in keys)or regular_bytes(journal,1024*1024)!=original:return unavailable
        for k in('oom','restarting'):
            if type(after[k])is not bool:return unavailable
        for k in('exit','restarts'):
            if type(after[k])is not int or not 0<=after[k]<=2147483647:return unavailable
        if after['status']not in ('created','running','paused','restarting','removing','exited','dead'):return unavailable
        health=after['health'];logs=[]
        if health is not None:
            if (type(health)is not dict or set(health)!={'status','streak','logs'}or health['status']not in('starting','healthy','unhealthy')
                    or type(health['streak'])is not int or not 0<=health['streak']<=2147483647
                    or type(health['logs'])is not list or len(health['logs'])>5):return unavailable
            for log in health['logs']:
                if type(log)is not dict or set(log)!={'exit','start','end'}or type(log['exit'])is not int or not -1<=log['exit']<=255:return unavailable
                # No raw timestamps exported. Typed exit sequence alone has no identity.
                if any(type(log[k])is not str or len(log[k])>64 for k in('start','end')):return unavailable
                logs.append(log['exit'])
        return {'status':'observed','container_state':after['status'],'container_exit':after['exit'],'oom_killed':after['oom'],
                'restarting':after['restarting'],'restart_count':after['restarts'],'health_status':health['status']if health else'absent',
                'failing_streak':health['streak']if health else None,'health_exit_codes':logs}
    except Exception:return unavailable

@contextmanager
def observe_journey(q,record,*,health_context=None):
    """Observe the original producer results; never interpret private output.

    This private module instance is used by one sequential ceremony. Restore its
    original callables on every exit; no command, argument, result or error changes.
    A returned command followed by an assertion is not a command-failure claim.
    """
    original=q.run;health=q.wait_for_local
    record.update(stage='qualification-entry',producer='not-started',exit_code=None)
    def tracked(name,*args,**kwargs):
        record.pop('admission_error_class',None)
        record.pop('install_receipt',None)
        record.pop('health_receipt',None)
        record.pop('health_projection',None)
        record.update(stage=JOURNEY_STAGES.get(name,'other-qualification-command'),producer='entered',exit_code=None)
        try:result=original(name,*args,**kwargs)
        except BaseException:
            record['producer']='raised'
            # q.run writes this exact status before its expected nonzero error.
            # Missing/unreadable status is uncertainty, never inferred success.
            if name in JOURNEY_STAGES and len(args)>=2:
                try:
                    with (Path(args[1])/(name+'.exit')).open('rb')as status:raw=status.read(9)
                    if len(raw)<=8 and re.fullmatch(rb'-?[0-9]{1,3}\n',raw):
                        code=int(raw);record['exit_code']=code if -255<=code<=255 else None
                except OSError:pass
            if name=='focused-public-install'and len(args)>=2:
                record['install_receipt']=retained_install_receipt(args[1])
                if record['install_receipt']and record['install_receipt']['phase']=='health':
                    from tools.release.native_runtime_probe import regular_bytes
                    try:record['health_receipt']=health_phase_receipt(regular_bytes(Path(args[1])/'focused-public-install.stderr',1024*1024))
                    except (OSError,ValueError):record['health_receipt']=None
                    if health_context is not None:record['health_projection']=failed_health_projection(health_context,args[1])
            if name=='fixture-full-runtime-admission'and record['exit_code']==2:
                record['admission_error_class']=retained_admission_error(args[1])
            raise
        code=result.returncode
        record.update(producer='returned',exit_code=code if type(code)is int and -255<=code<=255 else None)
        return result
    def checked_health(*args,**kwargs):
        record.update(stage='application-health',producer='entered',exit_code=None)
        try:result=health(*args,**kwargs)
        except BaseException:
            record['producer']='raised';raise
        record['producer']='returned';return result
    q.run=tracked;q.wait_for_local=checked_health
    try:yield
    finally:q.run=original;q.wait_for_local=health

def essential(value,source,*,diagnostics=None):
    evidence=Path(value['evidence']);private=Path(value['private'])
    evidence.mkdir(mode=0o700);private.mkdir(mode=0o700)
    record={'runtime_source_revision':value['source_revision'],'runtime_source_snapshot':value['source_snapshot'],
        'adapter_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'maintained_qualifier_sha256':hashlib.sha256((source/'tools/compose_release_qualification.py').read_bytes()).hexdigest(),
        'platform':PLATFORM,'before_execution':True,'scope':'native fixture-signed unclaimed LOCAL install/stop/cold backup/external verify-before-extract/import/restore/admit/start/health/final stop; no production/Qualys claim'}
    (evidence/'invocation.json').write_text(json.dumps(record,indent=2)+'\n')
    sys.path.insert(0,str(source))
    spec=importlib.util.spec_from_file_location('_hosted_maintained_qualifier',source/'tools/compose_release_qualification.py')
    q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)
    with observe_journey(q,diagnostics if diagnostics is not None else {},health_context=value):
        try:
            q.qualify_inventory_cause_fixture(bundle=Path(value['bundle']),fixture=Path(value['fixture']),
                image_id=value['image_id'],source_revision=value['source_revision'],source_snapshot=value['source_snapshot'],
                platform=PLATFORM,private=private,evidence=evidence)
            admission=json.loads((evidence/'retained-fixture.json').read_text())['admission']
            environment=q.trusted_launcher_environment(private/'restored-minimal-host-path',admission)
            state=private/'instance';entry=private/'trusted-offline-entry.sh'
            if entry.is_symlink()or not entry.is_file():raise ValueError('original externally authenticated entry required')
            q.run('essential-restored-public-start',['sh',str(entry),'start','--directory',str(state)],evidence,env=environment)
            q.wait_for_local('http://127.0.0.1:46180',evidence)
            q.run('essential-restored-public-stop',['sh',str(entry),'stop','--directory',str(state)],evidence,env=environment)
            (evidence/'public-summary.json').write_text(json.dumps({'status':'passed','platform':PLATFORM,
                'source_revision':value['source_revision'],'source_snapshot':value['source_snapshot'],
                'signed_install_stop_cold_backup_verify_before_extract_restore_admit_health_final_stop':True,
                'scope':'native fixture-signed development LOCAL only; scanner/production/hardware-independent acceptance unclaimed'},indent=2)+'\n')
        finally:
            # Retain raw private evidence/resources on uncertainty. Never upload
            # this directory wholesale: it can contain capabilities and owner data.
            source_binding(value)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('stage',choices=('prepare-db-context','build-q','essential'));p.add_argument('--request',type=Path,required=True)
    p.add_argument('--expected-request-sha256',required=True);p.add_argument('--plan-only',action='store_true')
    a=p.parse_args();os.umask(0o077)
    try:
        value=read_request(a.request,a.expected_request_sha256,a.stage);source=source_binding(value)
        if a.plan_only:
            print(json.dumps({'stage':a.stage,'platform':PLATFORM,'source_revision':value['source_revision'],
                'command':q_command(value)if a.stage=='build-q'else'prepare exact canonical upstream DB context'if a.stage=='prepare-db-context'else'unchanged qualify_inventory_cause_fixture + restored public start/health/stop',
                'executed':False},sort_keys=True));return 0
        if a.stage=='prepare-db-context':
            prepare_db_context(Path(value['db_source_directory']),Path(value['evidence']));return 0
        require_native()
        if a.stage=='build-q':return subprocess.run(q_command(value),cwd=source).returncode
        essential(value,source);return 0
    except Exception:
        print('hosted ARM essential stage failed closed; retain private evidence',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
