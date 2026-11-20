"""Hosted native ARM LOCAL journey adapter; no signer or trust bypass.

Run only after independently checked native artifacts, genuine ephemeral log,
fixture Q and signed two-child graph exist. No infrastructure is started here.
The artifact/runtime source P and this adapter R remain distinct evidence fields.
"""
from __future__ import annotations
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

def essential(value,source):
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
